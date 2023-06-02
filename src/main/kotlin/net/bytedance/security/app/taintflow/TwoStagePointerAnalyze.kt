/*
* Copyright 2022 Beijing Zitiao Network Technology Co., Ltd.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


package net.bytedance.security.app.taintflow

import kotlinx.coroutines.*
import net.bytedance.security.app.Log
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.engineconfig.isLibraryClass
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.pointer.PLObject
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.pointer.PointerFactory
import net.bytedance.security.app.util.profiler
import net.bytedance.security.app.util.runInMilliSeconds
import net.bytedance.security.app.util.toSortedMap
import net.bytedance.security.app.util.toSortedSet
import soot.*
import soot.jimple.*
import soot.jimple.internal.*

class TwoStagePointerAnalyze(
    val name: String, //for debug,
    val entryMethod: SootMethod,
    val ctx: AnalyzeContext,
    val traceDepth: Int,
    private val pointerPropagationRule: IPointerFlowRule,
    private val taintFlowRule: IVariableFlowRule,
    private val methodAnalyzeMode: IMethodAnalyzeMode,
    private val analyzeTimeInMilliSeconds: Long,
) {
    val pt: PointerFactory get() = ctx.pt
    private val st = StmtTransfer(ctx, pt, this)
    private val orh = ObscureRuleHandler(ctx, pt)


    //key is a  method call site,value are callee functions.
    private var callGraph: MutableMap<String, MutableSet<SootMethod>> = HashMap()
    private var thisStageStart: Long = 0


    private var patchedMethods: MutableSet<SootMethod> = HashSet()

    private var returnPointerMap: MutableMap<SootMethod, MutableSet<PLPointer>> = HashMap()

    /*
    The following three maps are specifically used to analyze method calls like  obj.func(A1, A2, A3).
    stmtMethodMap: key is the stmt,value is the caller method
    stmtPtrMap: key is the stmt, value is obj(this)
    stmtObjMap:key is the stmt,  value is the object set that this points to
     */

    private var stmtMethodMap: MutableMap<Stmt, SootMethod> = HashMap()
    private var stmtPtrMap: MutableMap<Stmt, PLLocalPointer> = HashMap()
    private var stmtObjMap: MutableMap<Stmt, MutableSet<PLObject>> = HashMap()


    private var pseudoObjectOrFieldIndex = 0

    init {
        profiler.addTwoStagePointerAnalyzeCount()
    }

    private var scope: CoroutineScope? = null
    private fun canContinueAnalyze(): Boolean {
        return scope!!.isActive
    }

    /**
    The entrance of taint analysis and pointer analysis
     */
    suspend fun doPointerAnalyze() {
        val localScope = CoroutineScope(Dispatchers.Default)
        profiler.startPointAnalyze(name)
        thisStageStart = System.currentTimeMillis()
        try {
            val job = localScope.launch(Dispatchers.Default) {
                scope = this
                analyzeMethod(entryMethod, null, 0)
            }
            runInMilliSeconds(job, analyzeTimeInMilliSeconds, "$name-step1") {}
        } catch (ex: Exception) {
            ex.printStackTrace()
        }
        yield()
        Log.logInfo("$name fistStageAnalyze finished")
        thisStageStart = System.currentTimeMillis()
        try {
            val job = localScope.launch(Dispatchers.Default) {
                scope = this
                secondStageAnalyze()
            }
//            job.join()
            runInMilliSeconds(job, analyzeTimeInMilliSeconds, "$name-step2") {}
        } catch (ex: Exception) {
            ex.printStackTrace()
        }
        profiler.stopPointAnalyze(name)
        Log.logInfo("$name secondStageAnalyze finished, \nbaseInfo=${ctx.baseInfo()}")
    }

    /**
     * process stmt like r=a.f(a1,a2,a3)
     * @param sootMethod the method f
     * @param recvPtr r if exists
     * @param curTraceDepth the depth of the call stack
     * todo add @return to simplify the process,for example:
     *  r0=a.f() a.r1->a.@return a.r2->a.@return   a.@return ->caller.r0
     */
    private suspend fun analyzeMethod(
        sootMethod: SootMethod, recvPtr: PLLocalPointer?, curTraceDepth: Int
    ): Boolean {
        if (curTraceDepth > traceDepth) {
            return true
        }
        yield()
        if (!canContinueAnalyze()) {
            return false
        }
        var line = 0
        for (unit in sootMethod.activeBody.units) {
            line++
            val stmt = unit as Stmt
            if (!canContinueAnalyze()) {
                return false
            }
            analyzeStmtInterProcedure(stmt, sootMethod, recvPtr, line, curTraceDepth + 1)
        }
        return false
    }


    private suspend fun analyzeStmtInterProcedure(
        stmt: Stmt, method: SootMethod, recvPtr: PLLocalPointer?, line: Int, curTraceDepth: Int
    ) {
        if (stmt is JInvokeStmt) {
            val invokeExpr = stmt.getInvokeExpr()
            val callSite = createCallSite(method, line)
            if (invokeExpr is JStaticInvokeExpr || invokeExpr is JDynamicInvokeExpr) {
                staticInvoke(
                    stmt, method, callSite, null, invokeExpr as AbstractInvokeExpr, line, curTraceDepth
                )
            } else if (invokeExpr is InstanceInvokeExpr) {
                val basePtr = instanceInvoke(stmt, method, callSite, null, invokeExpr, line, curTraceDepth)
                basePtr?.let { addToFixPointAlgoCache(it, method, stmt) }
            }
        } else if (stmt is JIdentityStmt) {
            // l2 := @parameter1: int
            st.identityStmt(stmt, method)
        } else if (stmt is JAssignStmt) {
            val leftExpr = stmt.leftOp
            when (val rightExpr = stmt.rightOp) {
                is JStaticInvokeExpr -> {
                    val callSite = createCallSite(method, line)
                    val localCallRecv = leftExpr as JimpleLocal
                    val localRecvPtr = pt.allocLocal(method, localCallRecv.name, localCallRecv.type)
                    staticInvoke(
                        stmt, method, callSite, localRecvPtr, rightExpr, line, curTraceDepth
                    )
                }

                is JDynamicInvokeExpr -> {
                    val callSite = createCallSite(method, line)
                    val localCallRecv = leftExpr as JimpleLocal
                    val localRecvPtr = pt.allocLocal(method, localCallRecv.name, localCallRecv.type)
                    staticInvoke(
                        stmt, method, callSite, localRecvPtr, rightExpr, line, curTraceDepth
                    )
                }

                is InstanceInvokeExpr -> {
                    val callSite = createCallSite(method, line)
                    val recvOp = leftExpr as JimpleLocal
                    val localRecvPtr = pt.allocLocal(method, recvOp.name, recvOp.type)
                    val basePtr = instanceInvoke(stmt, method, callSite, localRecvPtr, rightExpr, line, curTraceDepth)
                    basePtr?.let { addToFixPointAlgoCache(it, method, stmt) }
                }

                is AbstractBinopExpr -> {
                    // a = 3 + 4
                    // a = b + c
                    // a = A.b + 3
                    // a = 3 + b
                    st.binaryOp(leftExpr as JimpleLocal, rightExpr, method)
                }

                is UnopExpr -> {
                    // $i1 = lengthof $r1
                    // $i1 = neg $i0
                    st.unaryOp(leftExpr as JimpleLocal, rightExpr, method)
                }

                is JCastExpr -> {
                    // a = (A)b
                    // a = (int)4
                    st.castExpr(leftExpr as JimpleLocal, rightExpr, method)
                }

                is JArrayRef -> {
                    // 'a = b[2]' as load
                    st.loadArray(leftExpr as JimpleLocal, rightExpr, method)
                }

                is JimpleLocal -> {
                    val rightPtr = pt.allocLocal(method, rightExpr.name, rightExpr.getType())
                    when (leftExpr) {
                        is JInstanceFieldRef -> {
                            // a.b = c
                            val basePtr = st.storeInstanceLocal(leftExpr, rightPtr, method)
                            addToFixPointAlgoCache(basePtr, method, stmt)
                        }

                        is StaticFieldRef -> {
                            // A.b = c
                            val leftPtr = pt.allocStaticField(leftExpr.field)
                            if (rightExpr.getType() is ArrayType && ctx.pointerToObjectSet.containsKey(rightPtr)) {
                                val objs =
                                    HashSet(ctx.getPointToSet(rightPtr)!!) //copy to avoid ConcurrentModificationException
                                for (obj in objs) {
                                    val objPtr = pt.allocObjectField(obj, PLUtils.DATA_FIELD, UnknownType.v())
                                    ctx.addPtrEdge(objPtr, rightPtr)
                                }
                            }
                            ctx.addPtrEdge(rightPtr, leftPtr)
                        }

                        is JimpleLocal -> {
                            // a = c
                            val leftPtr = pt.allocLocal(method, leftExpr.name, leftExpr.getType())
                            ctx.addPtrEdge(rightPtr, leftPtr)
                        }

                        else -> { // JArrayRef
                            // arr[1] = c
                            st.storeArrayLocal(leftExpr as JArrayRef, rightPtr, method)
                        }
                    }
                }

                is JInstanceFieldRef -> {
                    // a = c.b
                    val basePtr = st.loadLocalInstance(leftExpr as JimpleLocal, rightExpr, method)
                    addToFixPointAlgoCache(basePtr, method, stmt)
                }

                is StaticFieldRef -> {
                    // a = A.b
                    st.assignStaticField(leftExpr as JimpleLocal, rightExpr, method)
                }

                is AnyNewExpr -> {
                    // a = new A()
                    st.newInstant(leftExpr as JimpleLocal, rightExpr, method, line)
                }

                is Constant -> { // StringConstant,NullConstant,ClassConstant,NumericConstant
                    when (leftExpr) {
                        is JInstanceFieldRef -> {
                            // a.b = "33"
                            st.storeInstanceConst(leftExpr, rightExpr, method)
                        }

                        is JArrayRef -> {
                            // arr[2] = "test" as store
                            st.storeArrayConst(leftExpr, rightExpr, method)
                        }

                        is StaticFieldRef, is JimpleLocal -> {
                            // a = "str"
                            // A.a = "str"
                            st.storeLocalOrStaticFieldConst(leftExpr, rightExpr, method)
                        }

                        else -> {
                            throw Exception("unknown stmt=$stmt")
                        }
                    }
                }
            }
        } else if (stmt is JReturnStmt) {
            st.stmtReturn(recvPtr, stmt, method)
        }
    }


    private suspend fun staticInvoke(
        stmt: Stmt,
        caller: SootMethod,
        callSite: String,
        recvPtr: PLLocalPointer?,
        invokeExpr: AbstractInvokeExpr,
        line: Int,
        curTraceDepth: Int
    ) {
        if (!canContinueAnalyze()) {
            return
        }
        val mode = methodAnalyzeMode.methodMode(invokeExpr.method)
        if (mode == MethodAnalyzeMode.Skip) {
            return
        }
        val callee = invokeExpr.method
        if (!checkAddCallGraph(callSite, callee)) {
            transferParams(invokeExpr, caller, callee)
            if (!checkAddRM(callee)) {
                if (mode == MethodAnalyzeMode.Obscure) {
                    patchedMethods.add(callee)
                    patchMethod(stmt, caller, callee, null, recvPtr, line)
                } else {
                    val isReachedMax = analyzeMethod(callee, recvPtr, curTraceDepth)
                    if (isReachedMax) {
                        removeRM(callee)
                    }
                }
            } else {
                if (recvPtr != null) {
                    if (patchedMethods.contains(callee)) {
                        patchMethod(stmt, caller, callee, null, recvPtr, line)
                    } else {
                        val retPtrSet = returnPointerMap[callee]
                        if (retPtrSet != null && retPtrSet.isNotEmpty()) {
                            for (retPtr in retPtrSet) {
                                ctx.addPtrEdge(retPtr, recvPtr)
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     *   ret=obj.f(arg1,arg2)
     *  @param stmt ret=obj.f(arg1,arg2)
     *  @param caller the method that contains the [stmt]
     *  @param callSite call site
     *  @param recvPtr ret if exists
     *  @param invokeExpr obj.f(arg1,arg2)
     *  @param line: stmt index
     *  @param curTraceDepth: max depth
     */
    private suspend fun instanceInvoke(
        stmt: Stmt,
        caller: SootMethod,
        callSite: String,
        recvPtr: PLLocalPointer?,
        invokeExpr: InstanceInvokeExpr,
        line: Int,
        curTraceDepth: Int
    ): PLLocalPointer? {
        if (!canContinueAnalyze()) {
            return null
        }
        val mode = methodAnalyzeMode.methodMode(invokeExpr.method)
        if (mode == MethodAnalyzeMode.Skip) {
            return null
        }
        // base.func()
        val baseName = invokeExpr.base.toString()
        val baseType = invokeExpr.base.type
        val basePtr = pt.allocLocal(caller, baseName, baseType)
        val baseObjs = ctx.getPointToSet(basePtr)
        val typeObjs: MutableSet<PLObject> = HashSet()

        if (baseObjs != null) {
            for (obj in baseObjs) {
                typeObjs.add(obj)
            }
        }

        if (typeObjs.size == 1) {
            val oneObj = typeObjs.iterator().next()
            val objType = oneObj.classType
            if (objType !is ArrayType) {
                val sc = Scene.v().getSootClassUnsafe(objType.toString(), false)
                if (sc != null && sc.isInterface && !isLibraryClass(sc.name)) {
                    val subClassSet = HashSet<SootClass>()
                    PLUtils.getAllSubCLass(sc, subClassSet)
                    for (newClass in subClassSet) {
                        if (isLibraryClass(newClass.name) || newClass.isInterface || newClass.isPhantom) {
                            continue
                        }
                        var isMatch = false
                        for (sm in newClass.methods) {
                            if (sm.subSignature == invokeExpr.methodRef.subSignature.toString()) {
                                isMatch = true
                                break
                            }
                        }
                        if (isMatch) {
                            val newObj = pt.allocObject(
                                newClass.type, getPseudoEntryMethod(), null, pseudoObjectOrFieldIndex++
                            )
                            typeObjs.add(newObj)
                        }
                    }
                }
            } else {
//                throw Exception("$oneObj ${objType} is ArrayType")
            }
        }
        var typeObjs2: Set<PLObject> = typeObjs
        if (typeObjs.isEmpty()) {
            typeObjs2 = makeNewObj(baseType, invokeExpr, basePtr)
        }
        for (typeObj in typeObjs2) {
            val callee = dispatchInstanceCall(invokeExpr, typeObj) ?: continue
            handleInstanceInvoke(
                stmt, callee, baseType, basePtr, caller, callSite, recvPtr, invokeExpr, line, curTraceDepth
            )
        }
        return basePtr
    }

    // a.f(a,b,c)
    // a.b=c
    //c =a.b
    private fun addToFixPointAlgoCache(basePtr: PLLocalPointer, method: SootMethod, stmt: Stmt) {
        if (!ctx.pointerToObjectSet.containsKey(basePtr)) {
            return
        }
        val allBaseObjs = ctx.getPointToSet(basePtr)
        val handledObjs = allBaseObjs?.toHashSet() ?: HashSet()
        stmtMethodMap[stmt] = method
        stmtObjMap[stmt] = handledObjs
        stmtPtrMap[stmt] = basePtr
    }


    fun addReturnPtrMap(callee: SootMethod, retPtr: PLPointer) {
        var retPtrSet = returnPointerMap[callee]
        if (retPtrSet == null) {
            retPtrSet = HashSet()
            returnPointerMap[callee] = retPtrSet
        }
        retPtrSet.add(retPtr)
    }

    fun makeNewObj(type: Type, v: Value, ptr: PLPointer): Set<PLObject> {
        val newObj = pt.allocObject(type, getPseudoEntryMethod(), v, pseudoObjectOrFieldIndex++)
        val objs = setOf(newObj)
        ctx.addObjToPTS(ptr, newObj)
        return objs
    }


    /**
     * r1="str",
     * @param nextPtr r1
     * @param constant "str"
     * @param constMethod method which contains this stmt(r1="str")
     */
    fun addConstValue(
        nextPtr: PLPointer,
        constant: Constant,
        constMethod: SootMethod,
    ): PLLocalPointer {
        val constPtr = pt.allocLocal(constMethod, PLUtils.constSig(constant), constant.type)
        constPtr.setConst(constant)
        ctx.addPtrEdge(constPtr, nextPtr)
        return constPtr
    }


    // a = b.c
    // b.c=a
    private fun loadOrStoreFixPointAlgo(
        local: JimpleLocal, field: JInstanceFieldRef, method: SootMethod, typeObjs: Set<PLObject>, isLoad: Boolean
    ) {
        val sootField = field.field
        val fieldName = sootField.name
        val base = field.base as JimpleLocal
        val basePtr = pt.allocLocal(method, base.name, base.type)
        val localPtr: PLPointer = pt.allocLocal(method, local.name, local.type)
        for (obj in typeObjs) {
            if (!canContinueAnalyze()) {
                return
            }
            val fieldObjPtr: PLPointer = pt.allocObjectField(obj, fieldName, sootField.type, sootField)
            val dataPtr = pt.allocObjectField(obj, PLUtils.DATA_FIELD, UnknownType.v())
            recordMethodTakesTime("fieldObjPtr=${fieldObjPtr.signature()},localPtr=${localPtr.signature()}") {
                if (isLoad) {
                    ctx.addPtrEdge(fieldObjPtr, localPtr)
                    if (ctx.pointerFlowGraph.containsKey(dataPtr)) {
                        ctx.addPtrEdge(dataPtr, localPtr)
                        ctx.addPtrEdge(basePtr, localPtr)
                    }
                } else {
                    ctx.addPtrEdge(localPtr, fieldObjPtr)
                    if (ctx.pointerFlowGraph.containsKey(dataPtr)) {
                        ctx.addPtrEdge(localPtr, dataPtr)
                        ctx.addPtrEdge(localPtr, basePtr)
                    }
                }
            }
        }
    }


    private fun transferParams(
        invokeExpr: InvokeExpr,
        caller: SootMethod,
        callee: SootMethod,
    ) {
        for ((argIndex, i) in (0 until invokeExpr.argCount).withIndex()) {
            val arg = invokeExpr.getArg(i)
            val paramType = invokeExpr.methodRef.getParameterType(i)
            if (arg is Constant) { // NumericConstant,StringConstant,NullConstant,ClassConstant
                val dstPtr: PLPointer = pt.allocLocal(callee, PLUtils.PARAM + argIndex, paramType)
                addConstValue(dstPtr, arg, caller)
            } else {
                val local = arg as JimpleLocal
                val srcPtr: PLPointer = pt.allocLocal(caller, local.name, local.type)
                val dstPtr: PLPointer = pt.allocLocal(callee, PLUtils.PARAM + argIndex, paramType)
                ctx.addPtrEdge(srcPtr, dstPtr)
            }
        }
    }


    private fun dispatchInstanceCall(invokeExpr: InstanceInvokeExpr, obj: PLObject): SootMethod? {
        // check they satisfied the hierarchy.
        if (!Scene.v().orMakeFastHierarchy.canStoreType(obj.classType, invokeExpr.base.type)) {
            return null
        }
        if (obj.classType is ArrayType) {
            return invokeExpr.method
        }
        // class of object
        var objClass = Scene.v().getSootClass(obj.classType.toString()) ?: return null
        val calleeClass = invokeExpr.methodRef.declaringClass

        if (invokeExpr is JSpecialInvokeExpr) {
            objClass = calleeClass
        }
        val methodSubSig = invokeExpr.methodRef.subSignature.toString()


        if (isLibraryClass(objClass.name)) {
            return PLUtils.dispatchCall(calleeClass, methodSubSig)
        }
        return PLUtils.dispatchCall(objClass, methodSubSig)

    }

    /**
     * for method's obscure analyze mode,
     * except user's specified obscure mode,there are other two case:
     * 1. exceed the max depth
     * 2. cannot find method body (for example ,cannot find any implementation  for an interface)
     * @param stmt where this method call occurs
     * @param caller where this stmt in
     * @param calleeMethod the callee method in stmt
     * @param basePtr calleeMethod's this pointer if calleeMethod is static, otherwise it's null
     * @param recvPtr c=a.f() if c exists
     * @param line callsite
     */
    private fun patchMethod(
        stmt: Stmt, caller: SootMethod, calleeMethod: SootMethod,
        basePtr: PLLocalPointer?, recvPtr: PLLocalPointer?, line: Int
    ) {
        var basePtr2 = basePtr
        //disallow flow taint to  Context
        if (basePtr2 != null && isContextPtr(basePtr2)) {
            basePtr2 = null
        }
        if (recvPtr != null) {
            val newObj = pt.allocObject(recvPtr.ptrType, caller, stmt.invokeExpr, line)
            ctx.addObjToPTS(recvPtr, newObj)
        }

        var baseDataPtrs: MutableSet<PLPointer>? = null
        if (basePtr2 != null) {
            baseDataPtrs = HashSet()
            for (baseObj in ctx.getPointToSet(basePtr2)!!) {
                val baseDataPtr: PLPointer = pt.allocObjectField(baseObj, PLUtils.DATA_FIELD, UnknownType.v())
                baseDataPtrs.add(baseDataPtr)
            }
//            }
        }
        val argPtrs: MutableList<PLPointer> = ArrayList()
        if (calleeMethod.parameterCount > 0) {
            val invokeExpr = stmt.invokeExpr
            for (i in 0 until invokeExpr.argCount) {
                val arg = invokeExpr.getArg(i)
                if (arg is Constant) { // NumericConstant,StringConstant,NullConstant,ClassConstant
                    val paramPtr = pt.allocLocal(calleeMethod, PLUtils.PARAM + i, arg.getType())
                    val constPtr = addConstValue(paramPtr, arg, caller)
                    argPtrs.add(constPtr)
                    //                    PLLog.logErr("add edge "+constPtr +" -> "+paramPtr);
                } else {
                    val argName = (arg as JimpleLocal).name
                    val argPtr = pt.allocLocal(caller, argName, arg.getType())
                    argPtrs.add(argPtr)
                }
            }
        }
        //pointer flow rule
        pointerPropagationRule.flow(calleeMethod)?.let {
            orh.addEdgeByRule(stmt, it, basePtr2, baseDataPtrs, recvPtr, argPtrs, true)

        }
        //taint flow rule and pointer flow rule are independent relationships
        taintFlowRule.flow(caller, calleeMethod).let {
            orh.addEdgeByRule(stmt, it, basePtr2, baseDataPtrs, recvPtr, argPtrs, false)
        }
    }


    private suspend fun handleInstanceInvoke(
        stmt: Stmt,
        callee: SootMethod,
        baseType: Type,
        basePtr: PLLocalPointer,
        caller: SootMethod,
        callSite: String,
        recvPtr: PLLocalPointer?,
        invokeExpr: InstanceInvokeExpr,
        line: Int,
        curTraceDepth: Int,
        processNewMethod: Boolean = true,
    ) {
        if (!canContinueAnalyze()) {
            return
        }
        if (!checkAddCallGraph(callSite, callee)) {
            val thisPtr: PLPointer = pt.allocLocal(callee, PLUtils.THIS_FIELD, baseType)
            ctx.addPtrEdge(basePtr, thisPtr)
            transferParams(invokeExpr, caller, callee)

            if (!checkAddRM(callee)) {
                if (!processNewMethod) {
                    return
                }
                val mode = methodAnalyzeMode.methodMode(callee)
                if (mode == MethodAnalyzeMode.Obscure) {
                    patchMethod(stmt, caller, callee, basePtr, recvPtr, line)
                    patchedMethods.add(callee)
                } else {
                    val isReachedMax = analyzeMethod(callee, recvPtr, curTraceDepth)
                    if (isReachedMax) {
                        removeRM(callee)
                    }
                }
            } else {
                if (patchedMethods.contains(callee)) {
                    patchMethod(stmt, caller, callee, basePtr, recvPtr, line)
                } else {
                    if (recvPtr != null) {
                        val retPtrSet = returnPointerMap[callee]
                        if (retPtrSet != null && retPtrSet.isNotEmpty()) {
                            for (retPtr in retPtrSet) {
                                ctx.addPtrEdge(retPtr, recvPtr)
                            }
                        }
                    } // if(callerRecv != null){
                } //
            }
        }
    }


    private suspend fun secondStageAnalyze() {
        val methodSigArr: MutableList<SootMethod> = ArrayList()
        val stmtArr: MutableList<Stmt> = ArrayList()
        val ptrArr: MutableList<PLLocalPointer> = ArrayList()
        val curObjArr: MutableList<Set<PLObject>> = ArrayList()
        while (true) {
            yield()
            if (!canContinueAnalyze()) {
                return
            }
            methodSigArr.clear()
            stmtArr.clear()
            ptrArr.clear()
            curObjArr.clear()
            val fixedPoint = isReachedFixPoint(methodSigArr, stmtArr, ptrArr, curObjArr)
            if (fixedPoint) {
                break
            }
            for (i in methodSigArr.indices) {
                if (!canContinueAnalyze()) {
                    return
                }
                fixPointAlgoWithObjs(methodSigArr[i], stmtArr[i], ptrArr[i], curObjArr[i])
            }
        }
    }

    private suspend fun fixPointAlgoWithObjs(
        caller: SootMethod,
        stmt: Stmt,
        basePtr: PLLocalPointer,
        typeObjs: Set<PLObject>
    ) {
        if (stmt.containsInvokeExpr()) {
            instanceInvokeWithObjs(caller, stmt, basePtr, typeObjs)
        } else if (stmt is JAssignStmt) {
            val leftOp = stmt.leftOp
            val rightOp = stmt.rightOp
            if (leftOp is JimpleLocal) {
                val fieldRef = rightOp as JInstanceFieldRef
                loadOrStoreFixPointAlgo(leftOp, fieldRef, basePtr.method, typeObjs, true)
            } else {
                val local = rightOp as JimpleLocal
                val fieldRef = leftOp as JInstanceFieldRef
                loadOrStoreFixPointAlgo(local, fieldRef, basePtr.method, typeObjs, false)
            }
        }
    }

    private suspend fun instanceInvokeWithObjs(
        caller: SootMethod, stmt: Stmt, basePtr: PLLocalPointer, typeObjs: Set<PLObject>
    ): PLLocalPointer {
        var recvPtr: PLLocalPointer? = null
        val invokeExpr: InstanceInvokeExpr
        if (stmt is JAssignStmt) {
            val callerRecv = stmt.leftOp as JimpleLocal
            recvPtr = pt.allocLocal(caller, callerRecv.name, callerRecv.type)
            invokeExpr = stmt.rightOp as InstanceInvokeExpr
        } else {
            invokeExpr = stmt.invokeExpr as InstanceInvokeExpr
        }
        val callSite = createCallSite(caller, stmt.javaSourceStartLineNumber)
        for (typeObj in typeObjs) {
            // below is the dispatch
            val callee = dispatchInstanceCall(invokeExpr, typeObj) ?: continue
            var curTraceDepth = 0
            if (traceDepth > 6) {
                curTraceDepth = traceDepth - 6
            }
            recordMethodTakesTime("$callSite:$callee") {
                handleInstanceInvoke(
                    stmt,
                    callee,
                    basePtr.ptrType,
                    basePtr,
                    caller,
                    callSite,
                    recvPtr,
                    invokeExpr,
                    stmt.javaSourceStartLineNumber,
                    curTraceDepth,
                    false
                )
            }
        }
        return basePtr
    }


    private fun isReachedFixPoint(
        methods: MutableList<SootMethod>,
        stmtArr: MutableList<Stmt>,
        ptrArr: MutableList<PLLocalPointer>,
        curObjArr: MutableList<Set<PLObject>>
    ): Boolean {
        for ((stmt, basePtr) in stmtPtrMap) {
            if (!stmtMethodMap.containsKey(stmt)) {
                continue
            }
            val method = stmtMethodMap[stmt]!!
            val curObjSet: MutableSet<PLObject> = ctx.getPointToSet(basePtr)?.toHashSet() ?: HashSet()
            val handledObjSet = stmtObjMap[stmt]!!
            curObjSet.removeAll(handledObjSet)
            handledObjSet.addAll(curObjSet)
            val iterator = curObjSet.iterator()
            while (iterator.hasNext()) {
                val obj = iterator.next()
                if (obj.isPseudoObj) {
                    iterator.remove()
                }
            }
            if (curObjSet.isEmpty()) {
                continue
            }

            methods.add(method)
            stmtArr.add(stmt)
            ptrArr.add(basePtr)
            curObjArr.add(curObjSet)
        }
        return methods.isEmpty()
    }


    private fun createCallSite(caller: SootMethod, line: Int): String {
        return "$caller:$line"
    }

    private fun checkAddCallGraph(callSite: String, callee: SootMethod): Boolean {
        var isInCG = true
        var dstSet = callGraph[callSite]
        if (dstSet == null) {
            dstSet = HashSet()
            callGraph[callSite] = dstSet
        }
        if (!dstSet.contains(callee)) {
            isInCG = false
            dstSet.add(callee)
        }
        return isInCG
    }

    private fun removeRM(method: SootMethod) {
        ctx.rm.remove(method)
    }

    private fun checkAddRM(methodSig: SootMethod): Boolean {
        var isInRM = true
        if (!ctx.rm.contains(methodSig)) {
            isInRM = false
            ctx.rm.add(methodSig)
        }
        return isInRM
    }

    @Suppress("unused")
    fun dump(): String {
        var s = """
            entryMethod=${entryMethod.signature},
            patchedMethods= ${patchedMethods.toSortedSet()},
            ReturnPtrMap=${returnPointerMap.toSortedMap()},
            stmtMethodMap=${stmtMethodMap.toSortedMap()},
            stmtPtrMap=${stmtPtrMap.toSortedMap()},
            stmtObjMap=${stmtObjMap.toSortedMap()},
            ptrIndexMap=${pt.ptrIndexMap.keys.toSortedSet()},
            objIndexMap=${pt.objIndexMap.keys.toSortedSet()},
        """.trimIndent()
        s += "PLContext={\n${ctx.dump()}\n}\n"
        return s
    }

    companion object {
        private var pseudoMethod: SootMethod? = null

        @Synchronized
        fun getPseudoEntryMethod(): SootMethod {
            if (pseudoMethod == null) {
                var clz = Scene.v().getSootClass(PLUtils.CUSTOM_CLASS)
                if (clz.isPhantom) {
                    PLUtils.createCustomClass()
                    clz = Scene.v().getSootClass(PLUtils.CUSTOM_CLASS)
                }
                pseudoMethod = PLUtils.entryMethod(clz, listOf(), false)
            }
            return pseudoMethod!!
        }

        inline fun recordMethodTakesTime(name: String, defaultTime: Int = 20000, action: () -> Unit) {
            val start = System.currentTimeMillis()
            action()
            val end = System.currentTimeMillis()
            if (end - start > defaultTime) {
                Log.logWarn("recordMethodTakesTime $name takes ${end - start}ms")
            }
        }

        private fun isContextPtr(ptr: PLPointer): Boolean {
            val type = ptr.ptrType
//            return type.toString() == "android.content.Context"
            var clz = Scene.v().getSootClassUnsafe(type.toString())
            while (clz != null) {
                if (clz.name == "android.content.Context") {
                    return true
                }
                if (clz.name == "java.lang.Object") {
                    return false
                }
                clz = clz.superclass
            }
            return false
        }
    }

}
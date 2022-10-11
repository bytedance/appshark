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


package net.bytedance.security.app.ruleprocessor


import net.bytedance.security.app.*
import net.bytedance.security.app.android.AndroidUtils
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.preprocess.CallSite
import net.bytedance.security.app.rules.DirectModeRule
import net.bytedance.security.app.rules.TaintPosition
import net.bytedance.security.app.taintflow.TaintAnalyzerData
import net.bytedance.security.app.util.toSortedMap
import soot.*
import soot.jimple.InstanceInvokeExpr
import soot.jimple.Stmt
import soot.jimple.StringConstant
import soot.jimple.internal.JAssignStmt
import soot.jimple.internal.JimpleLocal

class TaintRuleSourceSinkCollector(
    val ctx: PreAnalyzeContext,
    val rule: DirectModeRule,
    entries: List<SootMethod>,
) {
    val analyzerData = TaintAnalyzerData()

    val parameterSources = HashSet<PLLocalPointer>()
    val source = rule.source!!
    val sink: Map<String, SinkBody> = rule.sink

    //key is entry method
    private val hasSourceReturn = HashMap<SootMethod, Boolean>()

    init {
        entries.forEach {
            hasSourceReturn[it] = false
        }
    }

    fun collectSourceSinks() {
        processSource()
        processSink()
    }

    private fun processSink() {
        for ((sinkKey, sinkContentObj) in toSortedMap(sink)) {
            val sinkMethodSet = MethodFinder.checkAndParseMethodSig(sinkKey)

            if (sinkMethodSet.isEmpty()) {
                continue
            }
            for (sinkMethodSig in sinkMethodSet) {
                if (sinkContentObj.LibraryOnly == true && ctx.callGraph.isUserCode(sinkMethodSig)) {
                    continue
                }
                val sinkCallSites = ctx.findInvokeCallSite(sinkMethodSig)
                if (sinkCallSites.isEmpty()) {
                    continue
                }
                findSinkPointersForOneSinkRule(sinkContentObj, sinkCallSites)
            }
        }
    }

    private fun findSinkPointersForOneSinkRule(
        sinkContentObj: SinkBody,
        sinkCallSites: Set<CallSite>
    ) {
        for (callsite in sinkCallSites) {
            calcSinksAndParamCheck(
                sinkContentObj,
                setOf(callsite.stmt),
                callsite.method
            )
        }
    }

    private fun calcSinksAndParamCheck(
        sinkContentObj: SinkBody,
        sinkStmtSet: Set<Stmt>,
        sinkMethodCaller: SootMethod
    ) {

        for (sinkStmt in sinkStmtSet) {
            calcSinkPointers(
                sinkStmt,
                sinkContentObj,
                sinkMethodCaller
            )

        }
    }


    private fun calcSinkPointers(
        stmt: Stmt,
        sink: SinkBody,
        sinkMethodCaller: SootMethod
    ): Set<PLLocalPointer> {
        if (sink.TaintCheck == null || sink.TaintCheck.isEmpty()) {
            Log.logErr("${this.rule.name} sink  TaintCheck is empty")
            return emptySet()
        }
        val ptrSet: MutableSet<PLLocalPointer> = HashSet()
        val invokeExpr = stmt.invokeExpr
        val paramArr = sink.TaintCheck
        val paramTypeArr = sink.TaintParamType

        for (checkParamStr in paramArr) {
            val tp = TaintPosition(checkParamStr)
            if (tp.position == TaintPosition.This) {
                if (invokeExpr is InstanceInvokeExpr) {
                    val base = invokeExpr.base
                    val ptr = addPtrToEntry(stmt, base, sinkMethodCaller)
                    if (ptr != null) {
                        ptrSet.add(ptr)
                    }
                }
            } else if (tp.position == TaintPosition.Return) {
                //r$i0_1 = specialinvoke r0.<android.app.Service: int onStartCommand(android.content.Intent,int,int)>($r1, $i0, $i1);
                if (stmt is JAssignStmt) {
                    val leftExpr = stmt.leftOp
                    if (leftExpr is JimpleLocal) {
                        val ptr = addPtrToEntry(stmt, leftExpr, sinkMethodCaller)
                        if (ptr != null) {
                            ptrSet.add(ptr)
                        }
                    }
                }

            } else if (tp.position == TaintPosition.AllArgument) {
                for (arg in invokeExpr.args) {
                    if (!isValidType(paramTypeArr, arg.type)) {
                        continue
                    }
                    val ptr = addPtrToEntry(stmt, arg, sinkMethodCaller)
                    if (ptr != null) {
                        ptrSet.add(ptr)
                    }
                }
            } else if (tp.position >= 0) {
                if (tp.position < invokeExpr.argCount) {
                    val arg = invokeExpr.getArg(tp.position)
                    if (!isValidType(paramTypeArr, arg.type)) {
                        continue
                    }
                    val ptr = addPtrToEntry(stmt, arg, sinkMethodCaller)
                    if (ptr != null) {
                        ptrSet.add(ptr)
                    }
                }
            } else {
                throw Exception("unknown sink position for rule {${rule.name}")
            }
        }
        return ptrSet
    }

    private fun addPtrToEntry(
        stmt: Stmt,
        arg: Value,
        callerMethod: SootMethod,
    ): PLLocalPointer? {
        if (arg is StringConstant) {
            return analyzerData.allocPtrWithStmt(
                stmt,
                callerMethod,
                PLUtils.constStrSig(arg.value),
                RefType.v("java.lang.String"), false
            )
        } else if (arg is JimpleLocal) {
            return analyzerData.allocPtrWithStmt(
                stmt,
                callerMethod,
                arg.name,
                arg.getType(), false
            )
        }
        return null
    }

    private fun processSource() {
        if (source.ConstString.isNotEmpty()) {
            processSourceConstStr(source.ConstString)
        }
        if (source.StaticField.isNotEmpty()) {
            processSourceLoadField(source.StaticField)
        }
        if (source.Field.isNotEmpty()) {
            processSourceLoadField(source.Field)
        }
        if (source.Return != null) {
            processSourceReturn(source.parseReturn())
        }
        if (source.Param.isNotEmpty()) {
            processSourceMethodParameter(source.Param)
        }
        if (source.NewInstance.isNotEmpty()) {
            processSourceNewInstance(source.NewInstance)
        }
        if (source.UseJSInterface) {
            processSourceUseJSInterface()
        }

    }

    fun entryHasValidSource(entry: SootMethod): Boolean {
        if (source.ConstString.isNotEmpty() || source.StaticField.isNotEmpty() || source.Param.isNotEmpty() || source.NewInstance.isNotEmpty()) {
            return true
        }
        if (source.Return != null && hasSourceReturn[entry] == false) {
            return false
        }
        return true
    }

    /**
     * if a method is a jsb method, all arguments can be controlled by javascript.
     */
    private fun processSourceUseJSInterface() {
        if (ctx !is ContextWithJSBMethods) {
            return
        }
        for (sm in ctx.getJSBMethods()) {
            for (i in 0 until sm.parameterCount) {
                val paramType = sm.getParameterType(i)
                if (paramType is PrimType) {
                    continue
                }
                val ptr = analyzerData.allocSourcePtr(sm, PLUtils.PARAM + i, sm.getParameterType(i))
                parameterSources.add(ptr)
            }
        }
    }

    private fun processSourceLoadField(
        fields: List<String>,
    ) {
        for (field in fields) {
            val callsites = ctx.findFieldCallSite(field)
            for (callsite in callsites) {
                allocDirectEntrySourcePtr(callsite, callsite.method)
            }
        }
    }

    private fun processSourceNewInstance(
        jsonNewArray: List<String>,
    ) {
        for (obj in jsonNewArray) {
            val callsites = ctx.findInstantCallSiteWithSubclass(obj)
            for (callsite in callsites) {
                allocDirectEntrySourcePtr(callsite, callsite.method)
            }
        }
    }

    private fun processSourceMethodParameter(
        paramObj: Map<String, List<String>>
    ) {
        for ((methodKey, parameters) in paramObj) {
            val sourceMethodSet = MethodFinder.checkAndParseMethodSig(methodKey)
            if (sourceMethodSet.isEmpty()) {
                continue
            }
            for (sourceMethod in sourceMethodSet) {
                Log.logDebug("source $sourceMethod")
                for (param in parameters) {
                    val tp = TaintPosition(param)
                    if (tp.position == TaintPosition.AllArgument) {
                        for (i in 0 until sourceMethod.parameterCount) {
                            val ptr = analyzerData.allocSourcePtr(
                                sourceMethod,
                                PLUtils.PARAM + i,
                                sourceMethod.getParameterType(i),
                            )
                            parameterSources.add(ptr)
                        }
                    } else if (tp.isConcreteArgument()) {
                        val index = tp.position
                        if (index < sourceMethod.parameterCount) {
                            val ptr = analyzerData.allocSourcePtr(
                                sourceMethod,
                                PLUtils.PARAM + index,
                                sourceMethod.getParameterType(index),
                            )
                            parameterSources.add(ptr)
                        }
                    } else {
                        Log.logErr("source param position $param is not valid in ${rule.name}")
                    }
                }
            }
        }
    }

    private fun processSourceReturn(
        returns: Map<String, SourceReturn>,
    ) {
        for ((methodSig, cfg) in returns) {
            val sourceMethodSet = MethodFinder.checkAndParseMethodSig(methodSig)
            for (source in sourceMethodSet) {
                if (cfg.LibraryOnly == true && ctx.callGraph.isUserCode(source)) {
                    continue
                }

                val callsites = ctx.findInvokeCallSite(source)
                for (callsite in callsites) {
                    if (cfg.EntryInvoke && !getConfig().doWholeProcessMode) {
                        val sourceClass =
                            source.declaringClass
                        if (isMethodHasParent(source, sourceClass)) {
                            continue
                        }
                        if (!isSourceCalledInExportedComponents(callsite.method)) {
                            continue
                        }
                    }
                    if (!cfg.EntryInvoke) {
                        //if there is one source doesn't need EntryInvoke, then all entries are valid.
                        for ((k, _) in hasSourceReturn) {
                            hasSourceReturn[k] = true
                        }
                    }
                    allocDirectEntrySourcePtr(callsite, callsite.method)
                }
            }
        }
    }

    private fun isSourceCalledInExportedComponents(source: SootMethod): Boolean {
        val sourceClass = source.declaringClass
        var found = false
        for (entryMethod in this.hasSourceReturn.keys) {
            var entryClass = entryMethod.declaringClass
            if (AndroidUtils.entryCompoMap.containsKey(entryMethod)) {
                entryClass = AndroidUtils.entryCompoMap[entryMethod]
            }
            AndroidUtils.dummyToDirectEntryMap[entryMethod]?.let {
                entryClass = it.declaringClass
            }
            if (!Scene.v().orMakeFastHierarchy.canStoreClass(entryClass, sourceClass)) {
                continue
            }
            this.hasSourceReturn[entryMethod] = true
            found = true
        }
        return found

    }

    private fun allocDirectEntrySourcePtr(
        callsite: CallSite,
        sourceMethod: SootMethod,
    ) {
        if (callsite.stmt is JAssignStmt) {
            val local = callsite.stmt.leftOp as? JimpleLocal ?: return
            analyzerData.allocPtrWithStmt(callsite.stmt, sourceMethod, local.name, local.type, true)
        }
    }


    private fun processSourceConstStr(
        jsonStrArray: List<String>,
    ) {
        for (pattern in jsonStrArray) {
            val constCallSites = ctx.findConstStringPatternCallSite(pattern)
            for (callsite in constCallSites) {

                val constStrings = callsite.constString()
                for (constString in constStrings) {
                    if (!PLUtils.isStrMatch(pattern, constString)) {
                        continue
                    }
                    analyzerData.allocPtrWithStmt(
                        callsite.stmt,
                        callsite.method,
                        PLUtils.constStrSig(constString),
                        RefType.v("java.lang.String"), true
                    )
                }
            }
        }
    }


    companion object {
        /**
         * is method override of library method
         */
        private fun isMethodHasParent(method: SootMethod, declareClass: SootClass): Boolean {
            val declareSubMethodSig = method.subSignature
            val classSet: MutableSet<SootClass> = java.util.HashSet()
            getAllSuperClass(declareClass, classSet)
            for (parentClass in classSet) {
                val parentMethod = parentClass.getMethodUnsafe(declareSubMethodSig)
                if (parentMethod != null) {
                    return true
                }
            }
            return false
        }

        private fun getAllSuperClass(sc: SootClass, superClasses: MutableSet<SootClass>) {
            if (sc.hasSuperclass()) {
                val sootClass = sc.superclass
                superClasses.add(sootClass)
                //            logErr(sc.getName()+"'s super is "+sootClass.getName());
                getAllSuperClass(sootClass, superClasses)
            }
        }

        fun isValidType(paramTypeArr: List<String>?, type: Type): Boolean {
            if (paramTypeArr == null) {
                return true
            }
            for (typeStr in paramTypeArr) {
                if (typeStr == type.toString()) {
                    return true
                }
            }
            return false
        }

        fun hasReturn(taintCheckArr: List<String>): Boolean {
            for (c in taintCheckArr) {
                if (c == TaintPosition.RETURN) {
                    return true
                }
            }
            return false
        }
    }

}
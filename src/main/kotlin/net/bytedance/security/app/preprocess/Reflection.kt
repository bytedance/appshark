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


package net.bytedance.security.app.preprocess

import net.bytedance.security.app.Log.logErr
import net.bytedance.security.app.preprocess.Patch.resolveMethodException
import soot.*
import soot.Unit
import soot.jimple.*
import soot.jimple.internal.*

/**
 * patches for reflection
public void reflectionCall() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
Class clz = Class.forName("net.bytedance.security.app.preprocess.testdata.Apple");
Method setPriceMethod = clz.getMethod("setPrice", int.class);
Constructor appleConstructor = clz.getConstructor();
Object appleObj = appleConstructor.newInstance();
setPriceMethod.invoke(appleObj, 14);
Method getPriceMethod = clz.getMethod("getPrice");
System.out.println("Apple Price:" + getPriceMethod.invoke(appleObj));
}
find the concrete class and call the method
 */
object Reflection {
    private const val REFLECT_FOR_NAME = "<java.lang.Class: java.lang.Class forName(java.lang.String)>"
    private const val REFLECT_GET_CLASS = "<java.lang.Object: java.lang.Class getClass()>"
    private const val REFLECT_GET_METHOD_SIG =
        "<java.lang.Class: java.lang.reflect.Method getMethod(java.lang.String,java.lang.Class[])>"
    private const val REFLECT_GET_DECLARE_METHOD_SIG =
        "<java.lang.Class: java.lang.reflect.Method getDeclaredMethod(java.lang.String,java.lang.Class[])>"
    private const val INVOKE_METHOD_SIG =
        "<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>"

    fun tryInject(stmt: Stmt, caller: SootMethod): List<Unit> {
        val patchUnits: MutableList<Unit> = ArrayList()
        val invokeExpr = stmt.invokeExpr
        when (invokeExpr.methodRef.signature) {
            REFLECT_FOR_NAME -> {
                injectReflectForName(stmt, caller, patchUnits)
            }
            REFLECT_GET_CLASS -> {
                injectReflectGetClass(stmt, caller, patchUnits)
            }
            INVOKE_METHOD_SIG -> {
                injectXXClass(stmt, caller, patchUnits)
            }
        }
        return patchUnits
    }


    private fun injectReflectForName(stmt: Stmt, caller: SootMethod, patchUnits: MutableList<Unit>) {
        val arrayMap = arrayAnalyze(caller)
        val forNameRetMap = insertInstantStmt(stmt, caller, patchUnits)
        if (forNameRetMap.isEmpty()) {
            return
        }
        val getMethodRetMap = calcGetMethod(caller, arrayMap, forNameRetMap)
        if (getMethodRetMap.isEmpty()) {
            return
        }
        injectInvokeStmt(caller, arrayMap, getMethodRetMap, patchUnits)
    }

    private fun injectReflectGetClass(stmt: Stmt, caller: SootMethod, patchUnits: MutableList<Unit>) {
        val arrayMap = arrayAnalyze(caller)
        val forNameRetMap = insertGetClassInstantStmt(stmt, caller, patchUnits)
        if (forNameRetMap.isEmpty()) {
            return
        }
        val getMethodRetMap = calcGetMethod(caller, arrayMap, forNameRetMap)
        if (getMethodRetMap.isEmpty()) {
            return
        }
        injectInvokeStmt(caller, arrayMap, getMethodRetMap, patchUnits)
    }

    //xx.class()
    private fun injectXXClass(
        @Suppress("UNUSED_PARAMETER") stmt: Stmt,
        caller: SootMethod,
        patchUnits: MutableList<Unit>
    ) {
        if (!isXxClassReflection(caller.toString())) {
            return
        }
        val arrayMap = arrayAnalyze(caller)
        val forNameRetMap: Map<JimpleLocal, Pair<JimpleLocal, SootClass>> = insertxxClassInstantStmt(stmt, caller)
        if (forNameRetMap.isEmpty()) {
            return
        }
        val getMethodRetMap = calcGetMethod(caller, arrayMap, forNameRetMap)
        if (getMethodRetMap.isEmpty()) {
            return
        }
        injectInvokeStmt(caller, arrayMap, getMethodRetMap, patchUnits)
    }


    private fun injectInvokeStmt(
        entryMethod: SootMethod,
        arrayMap: Map<JimpleLocal, MutableList<Value>>,
        getMethodRetMap: Map<JimpleLocal?, Pair<JimpleLocal?, SootMethod>>,
        patchUnits: MutableList<Unit>
    ) {
        val stmtInvokeMap: MutableMap<Stmt, Stmt> = HashMap()
        for (unit in entryMethod.activeBody.units) {
            val stmt = unit as Stmt
            if (!stmt.containsInvokeExpr()) {
                continue
            }
            val invokeExpr = stmt.invokeExpr as? InstanceInvokeExpr ?: continue
            val baseVal = invokeExpr.base as? JimpleLocal ?: continue
            if (!getMethodRetMap.containsKey(baseVal)) {
                continue
            }
            val reflectInstanceInvoke = getMethodRetMap[baseVal]!!
            var retLocal: JimpleLocal? = null
            if (stmt is JAssignStmt) {
                val left = stmt.leftOp
                if (left is JimpleLocal) {
                    retLocal = left
                }
            }
            val invokeSig = invokeExpr.methodRef.signature
            if (invokeSig == INVOKE_METHOD_SIG) {
//                Value classVal =  instanceInvokeExpr.getArg(0);
                val argArrVal = invokeExpr.getArg(1) as? JimpleLocal ?: continue
                var methodArgs: List<Value>? = ArrayList()
                if (arrayMap.containsKey(argArrVal)) {
                    methodArgs = arrayMap[argArrVal]
                }
                val reflectDispatch = if (reflectInstanceInvoke.second.isStatic) {
                    Jimple.v().newStaticInvokeExpr(reflectInstanceInvoke.second.makeRef(), methodArgs)
                } else {
                    val sc = reflectInstanceInvoke.second.makeRef().declaringClass
                    if (sc.isInterface) {
                        Jimple.v().newInterfaceInvokeExpr(
                            reflectInstanceInvoke.first,
                            reflectInstanceInvoke.second.makeRef(),
                            methodArgs
                        )
                    } else {
                        Jimple.v().newVirtualInvokeExpr(
                            reflectInstanceInvoke.first,
                            reflectInstanceInvoke.second.makeRef(), methodArgs
                        )
                    }
                }
                if (retLocal != null) {
                    val assign = Jimple.v().newAssignStmt(retLocal, reflectDispatch)
                    stmtInvokeMap[assign] = stmt
                } else {
                    val invokeStmt = Jimple.v().newInvokeStmt(reflectDispatch)
                    stmtInvokeMap[invokeStmt] = stmt
                }
            }
        }
        patchUnits.addAll(stmtInvokeMap.keys.toList())
    }

    private fun calcGetMethod(
        entryMethod: SootMethod,
        arrayMap: Map<JimpleLocal, MutableList<Value>>,
        forNameRetMap: Map<JimpleLocal, Pair<JimpleLocal, SootClass>>
    ): Map<JimpleLocal?, Pair<JimpleLocal?, SootMethod>> {
        val getMethodRetMap: MutableMap<JimpleLocal?, Pair<JimpleLocal?, SootMethod>> = HashMap()
        for (unit in entryMethod.activeBody.units) {
            val stmt = unit as Stmt
            if (!stmt.containsInvokeExpr()) {
                continue
            }
            val invokeExpr = stmt.invokeExpr as? InstanceInvokeExpr ?: continue
            val baseVal = invokeExpr.base as? JimpleLocal ?: continue
            var retLocal: JimpleLocal? = null
            if (stmt is JAssignStmt) {
                val left = stmt.leftOp
                if (left is JimpleLocal) {
                    retLocal = left
                }
            }
            val invokeSig = invokeExpr.methodRef.signature
            if (invokeSig == REFLECT_GET_METHOD_SIG || invokeSig == REFLECT_GET_DECLARE_METHOD_SIG) {
                if (!forNameRetMap.containsKey(baseVal)) {
                    continue
                }
                val nameVal = invokeExpr.getArg(0)
                val argArrVal = invokeExpr.getArg(1)
                if (argArrVal !is JimpleLocal) {
                    continue
                }
                var methodName = nameVal.toString().replace("\"", "")

                if (nameVal is JimpleLocal) {
                    val right: Value? = getRightValue(entryMethod.signature, nameVal.toString())
                    if (right is JInstanceFieldRef) {
                        val field = right.field.toString()
                        val classInit = field.split(":".toRegex()).dropLastWhile { it.isEmpty() }
                            .toTypedArray()[0] + ": void <init>()>"
                        methodName = getRightValue(classInit, right.toString()).toString().replace("\"", "")
                    }
                    if (right is StaticFieldRef) {
                        val classClinit = right.toString().split(":".toRegex()).dropLastWhile { it.isEmpty() }
                            .toTypedArray()[0] + ": void <clinit>()>"
                        methodName = getRightValue(classClinit, right.toString()).toString().replace("\"", "")
                    }
                }
                else if (nameVal !is StringConstant){
                    continue
                }
                var methodArgs: List<Value>? = null
                if (arrayMap.containsKey(argArrVal)) {
                    methodArgs = arrayMap[argArrVal]
                }
                val reflectMethod = getMethod(forNameRetMap[baseVal]!!, methodName, methodArgs)
                if (reflectMethod != null) {
                    getMethodRetMap[retLocal] = Pair(forNameRetMap[baseVal]!!.first, reflectMethod)
                }
            }
        }
        return getMethodRetMap
    }

    private fun getMethod(
        instanceClass: Pair<JimpleLocal, SootClass>,
        methodName: String,
        methodArgs: List<Value>?
    ): SootMethod? {
        for (classMethod in instanceClass.second.methods) {
            if (classMethod.name == methodName) {
                var isAllParamEqual = true
                val sz = methodArgs?.size ?: 0
                if (sz != classMethod.parameterCount) {
                    isAllParamEqual = false
                }
                if (isAllParamEqual) {
                    return classMethod
                }
            }
        }
        return null
    }

    private fun arrayAnalyze(entryMethod: SootMethod): Map<JimpleLocal, MutableList<Value>> {
        val arrayMap: MutableMap<JimpleLocal, MutableList<Value>> = HashMap()
        for (unit in entryMethod.activeBody.units) {
            val stmt = unit as Stmt
            if (stmt is JAssignStmt) {
                val left = stmt.leftOp
                val right = stmt.rightOp
                if (left is JArrayRef) {
                    val baseLocal = left.base as JimpleLocal
                    if (arrayMap.containsKey(baseLocal)) {
                        arrayMap[baseLocal]!!.add(right)
                    }
                } else if (left is JimpleLocal) {
                    val leftLocal = stmt.leftOp as JimpleLocal
                    if (right is JNewArrayExpr) {
                        arrayMap[leftLocal] = ArrayList()
                    }
                }
            }
        }
        return arrayMap
    }

    private fun insertInstantStmt(
        forNameStmt: Stmt,
        entryMethod: SootMethod,
        patchUnits: MutableList<Unit>
    ): Map<JimpleLocal, Pair<JimpleLocal, SootClass>> {
        var localCnt = entryMethod.activeBody.localCount
        val reflectMap: MutableMap<JimpleLocal, Pair<JimpleLocal, SootClass>> = HashMap()

        if (forNameStmt !is JAssignStmt) {
            return reflectMap
        }
        val forNameInvoke = forNameStmt.invokeExpr
        val classNameArg = forNameInvoke.getArg(0) as? StringConstant ?: return reflectMap
        //
        val reflectClassName = classNameArg.value
        val reflectClass: SootClass? = try {
            Scene.v().getSootClassUnsafe(reflectClassName, false)
        } catch (e: Exception) {
            logErr("insertInstantStmt exception,reflectClassName is $reflectClassName")
            return reflectMap
        }

        if (reflectClass == null) {
            return reflectMap
        }

        val defaultMethodSubSig1 = "$reflectClassName getDefault()"
        val defaultMethodSubSig2 = "$reflectClassName getInstance()"
        val retName = "\$r" + ++localCnt
        val ret = Jimple.v().newLocal(retName, reflectClass.type) as JimpleLocal
        entryMethod.activeBody.locals.add(ret)

        val assignNewInstance: AssignStmt
        if (reflectClass.declaresMethod(defaultMethodSubSig1) || reflectClass.declaresMethod(defaultMethodSubSig2)) {
            var customInvoke = reflectClass.getMethodUnsafe(defaultMethodSubSig1)
            if (customInvoke == null) {
                customInvoke = reflectClass.getMethodUnsafe(defaultMethodSubSig2)
            }
            val staticInvokeExpr = Jimple.v().newStaticInvokeExpr(customInvoke!!.makeRef())
            assignNewInstance = Jimple.v().newAssignStmt(ret, staticInvokeExpr)
        } else {
            val newExpr = Jimple.v().newNewExpr(reflectClass.type)
            assignNewInstance = Jimple.v().newAssignStmt(ret, newExpr)
        }
        patchUnits.add(assignNewInstance)
        val invokeBaseLocal = forNameStmt.leftOp as JimpleLocal
        val pair = Pair(ret, reflectClass)
        reflectMap[invokeBaseLocal] = pair

        return reflectMap
    }

    private fun insertGetClassInstantStmt(
        forNameStmt: Stmt,
        entryMethod: SootMethod,
        patchUnits: MutableList<Unit>
    ): Map<JimpleLocal, Pair<JimpleLocal, SootClass>> {
        var localCnt = entryMethod.activeBody.localCount
        val reflectMap: MutableMap<JimpleLocal, Pair<JimpleLocal, SootClass>> = HashMap()

        if (forNameStmt !is JAssignStmt) {
            return reflectMap
        }
        val forNameInvoke = forNameStmt.invokeExpr
        val instanceInvokeExpr = forNameInvoke as InstanceInvokeExpr
        val baseVal = instanceInvokeExpr.base //r3.<java.lang....
        val classNameArg = getRightValue(entryMethod.toString(), baseVal.toString()) as? StringConstant
            ?: return reflectMap //r3 = "android.telephony.SmsManager";


        val reflectClassName = classNameArg.value
        val reflectClass = try {
            Scene.v().getSootClassUnsafe(reflectClassName, false)
        } catch (e: Exception) {
            logErr("insertGetClassInstantStmt exception,reflectClassName is $reflectClassName")
            return reflectMap
        }

        if (reflectClass == null) {
            return reflectMap
        }

        val defaultMethodSubSig1 = "$reflectClassName getDefault()"
        val defaultMethodSubSig2 = "$reflectClassName getInstance()"
        val retName = "\$r" + ++localCnt
        val ret = Jimple.v().newLocal(retName, reflectClass.type) as JimpleLocal
        entryMethod.activeBody.locals.add(ret)

        val assignNewInstance: AssignStmt
        if (reflectClass.declaresMethod(defaultMethodSubSig1) || reflectClass.declaresMethod(defaultMethodSubSig2)) {
            var customInvoke = reflectClass.getMethodUnsafe(defaultMethodSubSig1)
            if (customInvoke == null) {
                customInvoke = reflectClass.getMethodUnsafe(defaultMethodSubSig2)
            }
            val staticInvokeExpr = Jimple.v().newStaticInvokeExpr(customInvoke!!.makeRef())
            assignNewInstance = Jimple.v().newAssignStmt(ret, staticInvokeExpr)
        } else {
            val newExpr = Jimple.v().newNewExpr(reflectClass.type)
            assignNewInstance = Jimple.v().newAssignStmt(ret, newExpr)
        }
//        entryMethod.activeBody.units.insertAfter(assignNewInstance, forNameStmt)
        patchUnits.add(assignNewInstance)
        val invokeBaseLocal = forNameStmt.leftOp as JimpleLocal
        val pair = Pair(ret, reflectClass)
        reflectMap[invokeBaseLocal] = pair

        return reflectMap
    }

    @Suppress("unused")
    private fun insertClassInstantStmt(
        stmtSet: Set<Stmt>,
        entryMethod: SootMethod,
        patchUnits: MutableList<Unit>
    ): Map<JimpleLocal, Pair<JimpleLocal, SootClass>> {
        var localCnt = entryMethod.activeBody.localCount
        val reflectMap: MutableMap<JimpleLocal, Pair<JimpleLocal, SootClass>> = HashMap()

        for (forNameStmt in stmtSet) {
            if (!forNameStmt.containsInvokeExpr()) {   //invokeExpr instanceof InstanceInvokeExpr
                continue
            }
            val invokeExpr = forNameStmt.invokeExpr
            val invokeMethodSig = invokeExpr.methodRef.signature
            if (invokeMethodSig != INVOKE_METHOD_SIG) {
                continue
            }
            val arg1 = invokeExpr.getArg(0)
            if (!arg1.toString().startsWith("class")) {
                continue
            }
            val classNameArg = arg1.toString() // class "Landroid/telephony/SmsManager;"

            val reflectClassName = classNameArg.substring(8, classNameArg.length - 2)
                .replace("/", ".")
            val reflectClass: SootClass? = try {
                Scene.v().getSootClassUnsafe(reflectClassName, false)
            } catch (e: Exception) {
                logErr("insertClassInstantStmt exception,reflectClassName is $reflectClassName")
                continue
            }
            if (reflectClass == null) {
                continue
            }
            val forNameInvoke = forNameStmt.invokeExpr
            val instanceInvokeExpr = forNameInvoke as InstanceInvokeExpr
            val baseVal = instanceInvokeExpr.base
            val stmtReflectMethod = getStmt(entryMethod.toString(), baseVal.toString())
                ?: continue
            val invokeTmp = stmtReflectMethod.invokeExpr as? InstanceInvokeExpr ?: continue
            val baseFinal = invokeTmp.base

            val defaultMethodSubSig1 = "$reflectClassName getDefault()"
            val defaultMethodSubSig2 = "$reflectClassName getInstance()"
            val retName = "\$r" + ++localCnt
            val ret = Jimple.v().newLocal(retName, reflectClass.type) as JimpleLocal
            entryMethod.activeBody.locals.add(ret)

            var assignNewInstance: AssignStmt
            if (reflectClass.declaresMethod(defaultMethodSubSig1)
                || reflectClass.declaresMethod(defaultMethodSubSig2)
            ) {
                var customInvoke = reflectClass.getMethodUnsafe(defaultMethodSubSig1)
                if (customInvoke == null) {
                    customInvoke = reflectClass.getMethodUnsafe(defaultMethodSubSig2)
                }
                val staticInvokeExpr = Jimple.v().newStaticInvokeExpr(customInvoke!!.makeRef())
                assignNewInstance = Jimple.v().newAssignStmt(ret, staticInvokeExpr)
            } else {
                val newExpr = Jimple.v().newNewExpr(reflectClass.type)
                assignNewInstance = Jimple.v().newAssignStmt(ret, newExpr)
            }
//            entryMethod.activeBody.units.insertAfter(assignNewInstance, stmtReflectMethod)
            patchUnits.add(assignNewInstance)
            val invokeBaseLocal = baseFinal as JimpleLocal
            val pair = Pair(ret, reflectClass)
            reflectMap[invokeBaseLocal] = pair
        }
        return reflectMap
    }

    private fun insertxxClassInstantStmt(
        forNameStmt: Stmt,
        entryMethod: SootMethod
    ): Map<JimpleLocal, Pair<JimpleLocal, SootClass>> {
        var localCnt = entryMethod.activeBody.localCount
        val reflectMap: MutableMap<JimpleLocal, Pair<JimpleLocal, SootClass>> = HashMap()
        if (!forNameStmt.containsInvokeExpr()) {
            return reflectMap
        }
        val invokeExpr = forNameStmt.invokeExpr
        val invokeMethodSig = invokeExpr.methodRef.signature
        if (!invokeMethodSig.equals(INVOKE_METHOD_SIG)) {
            return reflectMap
        }
        val arg1 = invokeExpr.getArg(0)
        invokeExpr.getArg(1)

        val classNameArg = arg1.toString()
        val reflectClassName: String
        if (classNameArg.startsWith("class")) {
            reflectClassName = classNameArg.substring(8, classNameArg.length - 2).replace("/", ".")
        } else {
            reflectClassName = getReflectionClass(entryMethod.toString(), arg1.toString())
        }
        val reflectClass: SootClass?
        if (reflectClassName.isEmpty()) {
            return reflectMap
        }
        try {
            reflectClass = Scene.v().getSootClassUnsafe(reflectClassName, false)
        } catch (e: Exception) {
            logErr("insertxxClassInstantStmt exception,reflectClassName is " + reflectClassName)
            return reflectMap
        }
        if (reflectClass == null) {
            return reflectMap
        }
        val forNameInvoke = forNameStmt.invokeExpr
        val instanceInvokeExpr = forNameInvoke as InstanceInvokeExpr
        val baseVal = instanceInvokeExpr.base
        val stmtReflectMethod = getStmt(entryMethod.toString(), baseVal.toString())
        if (stmtReflectMethod == null || !stmtReflectMethod.containsInvokeExpr()) {
            return reflectMap
        }
        val invokeTmp = stmtReflectMethod.invokeExpr
        if (invokeTmp !is InstanceInvokeExpr) {
            return reflectMap
        }
        val baseFinal = invokeTmp.base

        val defaultMethodSubSig1 = "$reflectClassName getDefault()"
        val defaultMethodSubSig2 = "$reflectClassName getInstance()"
        val retName = "\$r" + (++localCnt)
        val ret = Jimple.v().newLocal(retName, reflectClass.type) as JimpleLocal
        entryMethod.activeBody.locals.add(ret)

        val assignNewInstance: AssignStmt
        if (reflectClass.declaresMethod(defaultMethodSubSig1) || reflectClass.declaresMethod(defaultMethodSubSig2)) {
            var customInvoke = reflectClass.getMethodUnsafe(defaultMethodSubSig1)
            if (customInvoke == null) {
                customInvoke = reflectClass.getMethodUnsafe(defaultMethodSubSig2)
            }
            val staticInvokeExpr = Jimple.v().newStaticInvokeExpr(customInvoke.makeRef())
            assignNewInstance = Jimple.v().newAssignStmt(ret, staticInvokeExpr)
        } else {
            val newExpr = Jimple.v().newNewExpr(reflectClass.getType())
            assignNewInstance = Jimple.v().newAssignStmt(ret, newExpr)
        }
        entryMethod.activeBody.units.insertAfter(assignNewInstance, stmtReflectMethod)

        val invokeBaseLocal = baseFinal as JimpleLocal
        val pair = Pair(ret, reflectClass)
        reflectMap[invokeBaseLocal] = pair

        return reflectMap
    }

    private fun getReflectionClass(methodName: String, leftParam: String): String {
        val sm = Scene.v().getMethod(methodName)
        if (sm.hasActiveBody()) {
            for (unit in sm.activeBody.units) {
                val stmt = unit as Stmt
                if (stmt is JAssignStmt) {
                    val right = stmt.rightOp
                    val left = stmt.leftOp
                    if (left.toString() == leftParam) {
                        if (right.toString()
                                .startsWith("(")
                        ) {
                            return right.toString().split(")").toTypedArray()[0].substring(1)
                        }
                        if (right is InvokeExpr) {
                            val reflectClass = resolveMethodException(right).toString()
                            if (reflectClass.contains(":")) {
                                return reflectClass.split(":").toTypedArray()[0].substring(1)
                            }
                        }
                    }
                }
                if (stmt is JIdentityStmt) {
                    val right = stmt.rightOp.toString()
                    val left = stmt.leftOp.toString()
                    if (left == leftParam && right.startsWith("@parameter")) {
                        return right.substring(13)
                    }
                }
            }
        }
        return ""
    }

    private fun getRightValue(methodSig: String?, leftArg: String): Value? {    //  $r4[2] = "hello"
        val sm = Scene.v().getMethod(methodSig)
        if (sm != null) {
            for (unit in sm.activeBody.units) {
                val stmt = unit as Stmt
                if (stmt is JAssignStmt) {
                    val leftExpr = stmt.leftOp.toString()
                    val rightExpr = stmt.rightOp
                    if (leftExpr == leftArg) {
                        return rightExpr
                    }
                }
            }
        }
        return null
    }

    private fun getStmt(methodSig: String?, leftArg: String): Stmt? {    // xx.class
        val sm = Scene.v().getMethod(methodSig)
        if (sm != null) {
            for (unit in sm.activeBody.units) {
                val stmt = unit as Stmt
                if (stmt is JAssignStmt) {
                    val leftExpr = stmt.leftOp.toString()
                    if (leftExpr == leftArg) {
                        return stmt
                    }
                }
            }
        }
        return null
    }

    fun isXxClassReflection(methodName: String?): Boolean {
        val sm = Scene.v().getMethod(methodName)
        if (sm.hasActiveBody()) {
            for (unit in sm.activeBody.units) {
                val stmt = unit as Stmt
                if (stmt.containsInvokeExpr()) {
                    val invokeExpr = stmt.invokeExpr
                    val invokeSig = invokeExpr.methodRef.signature
                    if (invokeSig == REFLECT_FOR_NAME || invokeSig == REFLECT_GET_CLASS) {
                        return false
                    }
                }
            }
        }
        return true
    }
}
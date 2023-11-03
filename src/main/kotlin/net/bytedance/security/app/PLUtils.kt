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


package net.bytedance.security.app

import net.bytedance.security.app.Log.logDebug
import net.bytedance.security.app.Log.logInfo
import soot.*
import soot.jimple.*
import soot.jimple.internal.JimpleLocal
import java.io.FileWriter
import java.io.IOException
import java.io.PrintWriter
import java.util.concurrent.atomic.AtomicInteger

object PLUtils {
    const val LevelNormal = "normal"                // 0x0
    const val LevelDanger = "dangerous"             // 0x1
    const val LevelSig = "signature"                // 0x2
    const val LevelSigOrSys = "signatureOrSystem"   // 0x3
    const val LevelInternal = "internal"            // 0x4
    const val LevelSigAndPri = "signature|privileged"   // 0x2+0x10

    var JAVA_SRC = "/java/"

    var DATA_FIELD = "@data"

    var THIS_FIELD = "@this"


    var PARAM = "@parameter"


    var CONST_STR = "@const_str:"
    const val CUSTOM_CLASS = "CustomClass"

    //entry method for whole program analyze
    const val CUSTOM_CLASS_ENTRY = "<$CUSTOM_CLASS: void main()>"
    const val CUSTOM_METHOD = "Main_Entry_"
    var classes = listOf<SootClass>()

    fun constStrSig(constant: String): String {
        return CONST_STR + constant
    }

    /**
     * fix ConcurrentModificationException error for  Scene.v().classes
     */
    fun updateSootClasses() {
        classes = Scene.v().classes.toList()
    }

    fun constSig(constant: Constant): String {
        return if (constant is StringConstant) {
            CONST_STR + constant.value
        } else if (constant is NumericConstant) {
            CONST_STR + constant.toString()
        } else if (constant is NullConstant) {
            CONST_STR + "null"
        } else {
            CONST_STR + constant.toString()
        }
    }


    fun isStrMatch(pattern: String, target: String): Boolean {
        val patternSub = pattern.replace("*", "")
        return if (pattern.startsWith("*") && pattern.endsWith("*")) {
            target.contains(patternSub)
        } else if (pattern.startsWith("*")) {
            target.endsWith(patternSub)
        } else if (pattern.endsWith("*")) {
            target.startsWith(patternSub)
        } else {
            target == patternSub
        }
    }

    fun writeFile(filePath: String, str: String) {
        try {
            val fw = FileWriter(filePath)
            val out = PrintWriter(fw)
            out.write(str)
            out.println()
            fw.close()
            out.close()
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }


    /**
     * get all subclass of sc, and save result to subClasses
     */
    fun getAllSubCLass(sc: SootClass, subClasses: HashSet<SootClass>) {
        if (sc.isInterface) {
            val subClassSet = Scene.v().orMakeFastHierarchy.getAllImplementersOfInterface(sc)
            if (subClassSet != null) {
                for (sootClass in subClassSet) {
                    if (!subClasses.contains(sootClass)) {
                        subClasses.add(sootClass)
                        getAllSubCLass(sootClass, subClasses)
                    }
                }
            }
        } else {
            val subClassSet = Scene.v().orMakeFastHierarchy.getSubclassesOf(sc)
            if (subClassSet != null) {
                for (sootClass in subClassSet) {
                    if (!subClasses.contains(sootClass)) {
                        subClasses.add(sootClass)
                        getAllSubCLass(sootClass, subClasses)
                    }
                }
            }
        }
    }

    fun createCustomClass() {
        val sClass = SootClass(CUSTOM_CLASS, Modifier.PUBLIC)
        // 'extends Object'
        sClass.superclass = Scene.v().getSootClass("java.lang.Object")
        Scene.v().addClass(sClass)
    }

    val entryId = AtomicInteger()


    @Synchronized
    fun createComponentEntry(
        superClass: SootClass,
        subClass: SootClass,
        lifecycleMethods: List<String>,
    ): SootMethod {
        val methodsToCall = ArrayList<SootMethod>()
        for (m in lifecycleMethods) {
            val targetMethod = superClass.getMethodUnsafe(m) ?: continue
            methodsToCall.add(targetMethod)
        }
        return entryMethod(subClass, methodsToCall, false)
    }

    /**
     * Find the nearest implementation of the overrideMethod in sc
     * set sc as Class C.
     * class A{
     * void f();
     * void g();
     * void h():
     * }
     * class B:A{
     * @overide
     * void f();
     * }
     * class C:A{
     * void g();
     * }
     * if overrideMethod is f,then return B.f
     * if overrideMethod is g,then return C.g
     * if overrideMethod is h,then return A.h
     * if overrideMethod is x, then return x
     */
    fun getNearestOverrideMethod(sc: SootClass, overrideMethod: SootMethod): SootMethod {
        var sc2: SootClass? = sc
        while (sc2 != null) {
            for (m in sc2.methods) {
                if (m.subSignature == overrideMethod.subSignature) {
                    return m
                }
            }
            if (sc2.hasSuperclass())
                sc2 = sc2.superclass
            else
                sc2 = null
        }
        return overrideMethod
    }

    /**
     * Create a new virtual function in CUSTOM_CLASS for sc that calls the functions in methodSet
     * @param sc: Virtual functions call some of the functions in this class
     * @param methodSet: method implemented in sc or super of sc
     * @param preventDuplication: make sure the virtual method unique or not
     */
    @Synchronized
    fun entryMethod(sc: SootClass, methodSet: List<SootMethod>, preventDuplication: Boolean = true): SootMethod {
        val className = CUSTOM_CLASS
        // Declare 'public class classname'
        val sClass = Scene.v().getSootClass(className)
        // Create the method, public static void main(String[])
        val scName = sc.name.replace(".", "_").replace("$", "_")
        var methodName = CUSTOM_METHOD + scName
        if (preventDuplication) {
            methodName += "_" + entryId.getAndIncrement()
        }
        val mainMethod = SootMethod(
            methodName,
            listOf(),
            VoidType.v(), Modifier.PUBLIC or Modifier.STATIC
        )
        sClass.methods.forEach {
            if (it.name == methodName) {
                return it
            }
        }
        try {
            sClass.addMethod(mainMethod)
            logInfo("entryMethod addMethod ${mainMethod.signature}")

            // create empty body
            val body = Jimple.v().newBody(mainMethod)
            mainMethod.activeBody = body
            val units = body.units


            // Add some locals, component r0
            val instant: Local = Jimple.v().newLocal("r0", sc.type)
            body.locals.add(instant)
            // r1 = new component
            val newExpr = Jimple.v().newNewExpr(sc.type)
            val assignStmt = Jimple.v().newAssignStmt(instant, newExpr)
            units.add(assignStmt)
            val realMethodSet: ArrayList<SootMethod> = ArrayList()
            for (m in sc.methods) {
                if (m.isConstructor) {
                    realMethodSet.add(m)
                }
            }

            realMethodSet.addAll(methodSet)
            for (overrideMethod in realMethodSet) {
                val targetMethod = getNearestOverrideMethod(sc, overrideMethod)
                //1.  ret
                var ret: JimpleLocal? = null
                if (targetMethod.returnType !is VoidType) {
                    val index = body.localCount
                    val localRet = Jimple.v().newLocal("v$index", targetMethod.returnType)
                    body.locals.add(localRet)
                    ret = localRet as JimpleLocal
                }
                //2. arguments
                val args: MutableList<Value> = ArrayList()
                for (i in 0 until targetMethod.parameterCount) {
                    val argType = targetMethod.getParameterType(i)
                    val index = body.localCount
                    val localArg = Jimple.v().newLocal("v$index", argType)
                    body.locals.add(localArg)
                    args.add(localArg)
                    if (argType is PrimType) {
                        when (argType) {
                            is FloatType -> {
                                val argAssignStmt = Jimple.v().newAssignStmt(localArg, FloatConstant.v(3f))
                                units.add(argAssignStmt)
                            }

                            is DoubleType -> {
                                val argAssignStmt = Jimple.v().newAssignStmt(localArg, DoubleConstant.v(4.0))
                                units.add(argAssignStmt)
                            }

                            else -> {
                                val argAssignStmt = Jimple.v().newAssignStmt(localArg, IntConstant.v(5))
                                units.add(argAssignStmt)
                            }
                        }
                    } else {
                        if (argType is ArrayType) {
                            val argNewExpr = Jimple.v().newNewArrayExpr(argType.baseType, IntConstant.v(2))
                            val argAssignStmt = Jimple.v().newAssignStmt(localArg, argNewExpr)
                            units.add(argAssignStmt)
                        } else if (argType is RefType) {
                            val argNewExpr = Jimple.v().newNewExpr(argType)
                            val argAssignStmt = Jimple.v().newAssignStmt(localArg, argNewExpr)
                            units.add(argAssignStmt)
                        }
                    }
                }
                //3. stmt
                val invokeExpr = if (targetMethod.isStatic) {
                    Jimple.v().newStaticInvokeExpr(targetMethod.makeRef(), args)

                } else {
                    try {
                        Jimple.v().newVirtualInvokeExpr(instant, targetMethod.makeRef(), args)
                    } catch (ex: Exception) {
                        Jimple.v().newInterfaceInvokeExpr(instant, targetMethod.makeRef(), args)
                    }
                }
                val assignStmt = if (ret != null) {
                    Jimple.v().newAssignStmt(ret, invokeExpr)
                } else {
                    Jimple.v().newInvokeStmt(invokeExpr)
                }
                units.add(assignStmt)
            }
            // insert "return"
            units.add(Jimple.v().newReturnVoidStmt())
            return mainMethod
        } catch (ex: Exception) {
            ex.printStackTrace()
            throw ex
        }
    }

    /**
     * create virtual entry method for each class,if it doesn't have a caller
     */
    private fun createTopMethodsCall(ctx: PreAnalyzeContext) {
        for ((clz, methods) in ctx.callGraph.getTopMethods()) {
            entryMethod(clz, methods.toList(), true)
        }
    }


    fun createWholeProgramAnalyze(ctx: PreAnalyzeContext) {
        createTopMethodsCall(ctx)
        createCustomMainEntry()
    }


    private fun createCustomMainEntry(): SootMethod {
        val className = CUSTOM_CLASS
        // Declare 'public class classname'
        val customClass = Scene.v().getSootClass(className)
        // Create the method, public static void main(String[])
        val methodName = "main"
        val mainMethod = SootMethod(
            methodName,
            listOf(),
            VoidType.v(), Modifier.PUBLIC or Modifier.STATIC
        )
        try {
            customClass.addMethod(mainMethod)
            logDebug("entryMethod addMethod ${mainMethod.signature}")

            // create empty body
            val body = Jimple.v().newBody(mainMethod)
            mainMethod.activeBody = body
            val units = body.units

            for (targetMethod in customClass.methods) {
                if (!targetMethod.isStatic) {
                    continue
                }
                if (targetMethod.name == "main") {
                    continue
                }

                val invokeStmt = Jimple.v().newInvokeStmt(
                    Jimple.v().newStaticInvokeExpr(targetMethod.makeRef(), listOf())
                )
                units.add(invokeStmt)
            }
            // insert "return"
            units.add(Jimple.v().newReturnVoidStmt())
        } catch (ex: Exception) {
            ex.printStackTrace()
            throw ex
        }
        return mainMethod
    }

    fun dispatchCall(sootClass: SootClass, methodSubSig: String): SootMethod? {
        var sootMethod = sootClass.getMethodUnsafe(methodSubSig)
        if (sootMethod == null) {
            sootMethod = if (sootClass.hasSuperclass()) {
                dispatchCall(sootClass.superclass, methodSubSig)
            } else {
                return null
            }
        }
        return sootMethod
    }


    fun dumpClass(className: String) {
        val clz = Scene.v().getSootClassUnsafe(className, false) ?: return
        println("class $className:")
        val it = clz.methodIterator()
        while (it.hasNext()) {
            val m = it.next()
            println(String.format("method:%s %s", m.signature, m.name))
            if (m.hasActiveBody()) {
                println(String.format("%s", m.activeBody))
            }
        }
    }

    fun findMatchedChildClasses(targetSet: Set<String>): MutableSet<SootClass> {
        val findMatchedClasses: MutableSet<SootClass> = HashSet()
        for (sc in classes) {
            if (sc.hasSuperclass() && targetSet.contains(sc.superclass.name)) {
                findMatchedClasses.add(sc)
                continue
            }
            for (intf in sc.interfaces) {
                if (targetSet.contains(intf.name)) {
                    findMatchedClasses.add(sc)
                }
            }
        }
        return findMatchedClasses
    }
}

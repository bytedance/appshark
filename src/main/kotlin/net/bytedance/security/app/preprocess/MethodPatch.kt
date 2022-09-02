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

import net.bytedance.security.app.Log
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.engineconfig.EngineConfig

import soot.*
import soot.Unit
import soot.jimple.*

/**
 * 1. do callback patch from config file
 * 2. do reflection patch
 * 3. do patch for patchFindviewByIdForWebview
 */
object MethodPatch {
    private var callBackEnhance = false


    private val floatConstant = FloatConstant.v(3f)
    private val doubleConstant = DoubleConstant.v(2.0)
    private val intConstant = IntConstant.v(1)
    private val nullConstant = NullConstant.v()
    private fun createNewInvokeUnit(sm: SootMethod, base: Value): Unit? {
        val args: MutableList<Value> = ArrayList()
        for (type in sm.parameterTypes) {
            if (type is PrimType) {
                if (type is FloatType) {
                    args.add(floatConstant)
                } else if (type is DoubleType) {
                    args.add(doubleConstant)
                } else {
                    args.add(intConstant)
                }
            } else {
                args.add(nullConstant)
            }
        }
        try {
            return if (sm.isStatic) {
                Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(sm.makeRef(), args))
            } else {
                Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(base as Local, sm.makeRef(), args))
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    private fun patchForStmt(stmt: Stmt, nextStmt: Stmt?, method: SootMethod, patchUnits: MutableList<Unit>) {
        calcCallbackPatchUnits(stmt, patchUnits)
        Reflection.tryInject(stmt, method, patchUnits)
        Patch.patchFindviewByIdForWebview(stmt, nextStmt, method, patchUnits)
    }

    /**
     *  do patch for constructor function
     * 1. patch from Callback config file, for example  if method F create a new instance of android.os.Handler,
     *      call the handleMessage
     *  2. if callBackEnhance is true, call all the internal class's function member.
     */
    private fun calcCallbackPatchUnits(stmt: Stmt, patchUnits: MutableList<Unit>) {
        val invokeExpr = stmt.invokeExpr as? InstanceInvokeExpr ?: return
        if (invokeExpr.methodRef.isConstructor) {
            val base = invokeExpr.base
            val declMethod =
                try {
                    Patch.resolveMethodException(invokeExpr)
                } catch (ex: Exception) {
                    Log.logInfo("calcCallbackPatchUnits: stmt=${stmt}")
                    Log.logInfo("calcCallbackPatchUnits ex= ${ex.stackTraceToString()}")
                    throw ex
                }
            val declClass = declMethod.declaringClass
            val baseCls = Scene.v().getSootClassUnsafe(base.type.toString(), false)
            if (declClass == baseCls && EngineConfig.callbackConfig.getCallBackConfig().containsKey(baseCls)) {
                for (subMethodSig in EngineConfig.callbackConfig.getCallBackConfig()[baseCls]!!) {
                    val sm = PLUtils.dispatchCall(baseCls, subMethodSig)
                    if (sm == null || !sm.isConcrete) {
                        continue
                    }
                    if (sm.declaringClass != declClass) {
                        continue
                    }
                    val newUnit = createNewInvokeUnit(sm, base)
                    if (newUnit != null) {
                        patchUnits.add(newUnit)
                    }
                }
            } else if (callBackEnhance && baseCls.isInnerClass) {
                val classInterfaces = baseCls.interfaces
                val subMethodSet: MutableSet<String> = HashSet()
                for (classInterface in classInterfaces) {
                    if (EngineConfig.callbackConfig.enhanceIgnore.contains(classInterface.name)) {
                        continue
                    }
                    for (method in classInterface.methods) {
                        subMethodSet.add(method.subSignature)
                    }
                }
                if (baseCls.hasSuperclass()) {
                    val superClass = baseCls.superclass
                    if (superClass.name != "java.lang.Object") {
                        for (superMethod in superClass.methods) {
                            subMethodSet.add(superMethod.subSignature)
                        }
                    }
                }
                if (subMethodSet.isEmpty()) {
                    return
                }
                for (sm in baseCls.methods) {
                    if (sm.isConstructor || sm.isStaticInitializer) {
                        continue
                    }
                    if (!subMethodSet.contains(sm.subSignature)) {
                        continue
                    }
                    val newUnit = createNewInvokeUnit(sm, base)
                    if (newUnit != null) {
                        patchUnits.add(newUnit)
                    }
                }
            }
        }
    }

    private fun injectAll(
        method: SootMethod,
        stmt: Stmt,
        nextStmt: Stmt?,
        methodUnits: UnitPatchingChain,
        iterator: MutableListIterator<Unit>,
    ) {
        if (stmt.containsInvokeExpr()) {
            val patchUnits: MutableList<Unit> = ArrayList()
            patchForStmt(stmt, nextStmt, method, patchUnits)
            if (patchUnits.isNotEmpty()) {
                methodUnits.insertAfter(patchUnits, stmt)
                for (patchUnit in patchUnits) {
                    iterator.add(patchUnit)
                    iterator.previous()
                }
                iterator.next()
            }
        }
    }

    fun processCallback(
        method: SootMethod,
        isCallBackEnhance: Boolean
    ) {
        callBackEnhance = isCallBackEnhance
        val tmpChain: MutableList<Unit> = ArrayList(method.activeBody.units)
        val iterator = tmpChain.listIterator()
        while (iterator.hasNext()) {
            val stmt = iterator.next() as Stmt
            val nextStmt = if (iterator.hasNext()) {
                val stmt2 = iterator.next() as Stmt
                iterator.previous()
                stmt2
            } else {
                null
            }
            injectAll(method, stmt, nextStmt, method.activeBody.units, iterator)
        }
    }
}

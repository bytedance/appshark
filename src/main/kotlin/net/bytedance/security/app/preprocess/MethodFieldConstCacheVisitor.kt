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
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.engineconfig.EngineConfig
import net.bytedance.security.app.engineconfig.isLibraryClass
import soot.*
import soot.jimple.*
import soot.jimple.internal.JAssignStmt
import soot.jimple.internal.JNewExpr
import soot.jimple.internal.JSpecialInvokeExpr
import soot.jimple.internal.JStaticInvokeExpr
import java.util.*

/**
 * Collect:
 * 1. all  function access,
 * 2. constants from the rule file
 * 3. field access from rule file
 * 4. new instance from rule file
 * 5. generate call graph for the whole app
 */
class MethodFieldConstCacheVisitor(
    val ctx: PreAnalyzeContext,
    val cache: MethodStmtFieldCache,
    private val constStrPatternFilter: Set<String>,
    private val filedFilter: Set<String>,
    private val newInstanceFilter: Set<String>
) :
    MethodVisitor {
    override fun visitMethod(method: SootMethod) {
        if (!method.isConcrete || !method.hasActiveBody()) {
            return
        }
        visitEachStmt(method, method.activeBody.units)
    }

    /**
     * Merge the results into ctx and generate the call graph
     */
    override fun collect(visitors: List<MethodVisitor>) {
        collectMethodInvoke(visitors)
        collectOthers(visitors)
    }

    /**
     * create call graph
     */
    private fun collectMethodInvoke(visitors: List<MethodVisitor>) {
        for (v in visitors) {
            val vv = v as MethodFieldConstCacheVisitor
            for ((callee, value) in vv.cache.methodDirectRefs) {
                val globalMethodCache = ctx.methodDirectRefs
                for (caller in value) {
                    ctx.callGraph.addEdge(caller.method, callee, true)
                }
                if (ctx.methodDirectRefs.containsKey(callee)) {
                    globalMethodCache[callee]!!.addAll(value)
                } else {
                    globalMethodCache[callee] = value
                }
            }
            for ((callee, value) in vv.cache.methodHeirRefs) {
                for (caller in value) {
                    ctx.callGraph.addEdge(caller.method, callee, false)
                }
            }
        }
    }


    private fun collectOthers(visitors: List<MethodVisitor>) {
        for (v in visitors) {
            val vv = v as MethodFieldConstCacheVisitor
            for ((key, value) in vv.cache.loadFieldRefs) {
                if (ctx.loadFieldRefs.containsKey(key)) {
                    ctx.loadFieldRefs[key]!!.addAll(value)
                } else {
                    ctx.loadFieldRefs[key] = value
                }
            }
            for ((key, value) in vv.cache.storeFieldRefs) {
                if (ctx.storeFieldRefs.containsKey(key)) {
                    ctx.storeFieldRefs[key]!!.addAll(value)
                } else {
                    ctx.storeFieldRefs[key] = value
                }
            }
            for ((key, value) in vv.cache.newInstanceRefs) {
                val clz = key.sootClass
                if (ctx.newInstanceRefs.contains(clz)) {
                    ctx.newInstanceRefs[clz]!!.addAll(value)
                } else {
                    ctx.newInstanceRefs[clz] = value
                }
            }
            for ((key, value) in vv.cache.constStringPatternMap) {
                if (ctx.constStringPatternMap.containsKey(key)) {
                    ctx.constStringPatternMap[key]!!.addAll(value)
                } else {
                    ctx.constStringPatternMap[key] = value
                }
            }
        }
    }

    private fun visitEachStmt(sootMethod: SootMethod, chain: UnitPatchingChain) {
        for (unit in chain) {
            val stmt = unit as Stmt
            val constStrings = getConstStringFromStmt(stmt)
            for (constString in constStrings) {
                for (pattern in constStrPatternFilter) {
                    if (PLUtils.isStrMatch(pattern, constString)) {
                        cache.addPattern(pattern, sootMethod, stmt)
                    }
                }
            }
            if (stmt.containsInvokeExpr()) {
                addMethodInvoke(stmt.invokeExpr, sootMethod, stmt)
            } else if (stmt is JAssignStmt) {
                val leftExpr = stmt.leftOp
                val rightExpr = stmt.rightOp
                if (rightExpr is JNewExpr) {
                    val typ = rightExpr.type as RefType
                    if (newInstanceFilter.contains(typ.className)) {
                        cache.addNewInstanceCache(typ, sootMethod, stmt)
                    }
                } else {
                    val (field, isStore) = if (rightExpr is StaticFieldRef) {
                        val field = rightExpr.fieldRef.resolve()
                        Pair(field, false)
                    } else if (leftExpr is StaticFieldRef) {
                        val field = leftExpr.fieldRef.resolve()
                        Pair(field, true)
                    } else if (rightExpr is InstanceFieldRef) {
                        val field = rightExpr.fieldRef.resolve()
                        Pair(field, false)
                    } else if (leftExpr is InstanceFieldRef) {
                        val field = leftExpr.fieldRef.resolve()
                        Pair(field, true)
                    } else {
                        continue
                    }
                    if (field == null) {
                        Log.logWarn("cannot found field ${stmt}")
                        continue
                    }

                    if (!filedFilter.contains(field.signature)) {
                        continue
                    }
                    if (isStore) {
                        cache.addStoreFieldCache(field, sootMethod, stmt)
                    } else {
                        cache.addLoadFieldCache(field, sootMethod, stmt)
                    }

                }
            }
        }
    }

    private fun addMethodInvoke(invokeExpr: InvokeExpr, sootMethod: SootMethod, stmt: Stmt) {
        val ref = invokeExpr.methodRef
        val m = try {
            ref.resolve()
        } catch (ex: Exception) {
            ex.printStackTrace()
            //ignore this error, todo how to handle this error?
            return
//            throw RuntimeException("resolve method exception,method:${ref.signature},ex=$ex")
        }
        if (m == null) {
            Log.logInfo("resolve method error,method:${ref.signature}")
            return
        }
        cache.addMethodDirectCache(m, sootMethod, stmt)
        if (invokeExpr is JSpecialInvokeExpr || invokeExpr is JStaticInvokeExpr) {
            return
        }
        if (!canMethodHasSubMethods(m)) {
            return
        }
        if (isLibraryClass(m.declaringClass.name)) {
            return
        }
        getAllHeirMethods(ref)?.let { methods ->
            methods.forEach { method ->
                cache.addMethodHeirCache(method, sootMethod, stmt)
            }
        }
    }

    companion object {


        fun getAllHeirMethods(method: SootMethodRef): MutableSet<SootMethod>? {
            if (isLibraryClass(method.declaringClass.name))
                return null
            val resolvedMethod = method.resolve()
            val possibleSet: MutableSet<SootClass> = HashSet()
            getAllHeirClassesWithSubMethodSig(method.declaringClass, possibleSet, resolvedMethod.subSignature)
            //            PLLog.logErr(methodSig+" possible classes "+possibleSet.toString());
            if (possibleSet.isNotEmpty()) {
                val subHeirCalleeSet: MutableSet<SootMethod> = HashSet()
                for (sc in possibleSet) {
                    val m = sc.getMethodUnsafe(method.subSignature)
                    if (m != null) {
                        subHeirCalleeSet.add(m)
                    } else {
                        Log.logInfo("getAllHeirMethods method error, method:$method, class:$sc")
                    }
                }
                subHeirCalleeSet.remove(resolvedMethod)
                return subHeirCalleeSet
            }
            return null
        }

        private fun getAllHeirClassesWithSubMethodSig(
            sc: SootClass,
            possibleClass: MutableSet<SootClass>,
            subMethodSig: String
        ) {
            val stack = Stack<SootClass>()

            if (!sc.declaresMethod(subMethodSig)) {
                getAllSuperClasses(sc, stack, possibleClass, subMethodSig)
            }
            getAllSubClasses(sc, stack, possibleClass, subMethodSig)
        }

        private fun getAllSubClasses(
            sc: SootClass,
            stack: Stack<SootClass>,
            superClasses: MutableSet<SootClass>,
            subMethodSig: String
        ) {
            stack.push(sc)
            if (sc.declaresMethod(subMethodSig)) {
                val m = sc.getMethodUnsafe(subMethodSig)
                if (m != null && m.isConcrete) {
                    superClasses.add(sc)
                }
            }
            if (stack.size > 8) {
                return
            }
            if (sc.isInterface) {
                val subClassSet = Scene.v().orMakeFastHierarchy.getAllImplementersOfInterface(sc)
                if (subClassSet != null) {
                    for (sootClass in subClassSet) {
                        if (EngineConfig.libraryConfig.isLibraryClass(sootClass.name)) {
                            continue
                        }
                        getAllSubClasses(sootClass, stack, superClasses, subMethodSig)
                        stack.pop()
                    }
                }
            } else {
                val subClassSet = Scene.v().orMakeFastHierarchy.getSubclassesOf(sc)
                if (subClassSet != null) {
                    for (sootClass in subClassSet) {
                        getAllSubClasses(sootClass, stack, superClasses, subMethodSig)
                        stack.pop()
                    }
                }
            }
        }

        private fun getAllSuperClasses(
            sc: SootClass,
            stack: Stack<SootClass>,
            superClasses: MutableSet<SootClass>,
            subMethodSig: String
        ) {
            stack.push(sc)
            if (EngineConfig.libraryConfig.isLibraryClass(sc.name)) {
                return
            }
            if (superClasses.size > 0) {
                return
            }
            if (sc.declaresMethod(subMethodSig)) {
                if (sc.getMethodUnsafe(subMethodSig).isConcrete) {
                    superClasses.add(sc)
                }
                return
            }
            if (stack.size > 8) {
                return
            }
            if (sc.hasSuperclass()) {
                val sootClass = sc.superclass
                getAllSuperClasses(sootClass, stack, superClasses, subMethodSig)
                stack.pop()
            }
        }

        fun getConstStringFromStmt(stmt: Stmt): List<String> {
            val lists = ArrayList<String>()
            for (valueBox in stmt.useAndDefBoxes) {
                val value = valueBox.value
                if (value is StringConstant) {
                    val constStr = value.value
                    lists.add(constStr)
                }
            }
            return lists
        }

        fun canMethodHasSubMethods(method: SootMethod): Boolean {
            return !(method.isConstructor || method.isStaticInitializer || method.isFinal || method.isNative || method.isPrivate || method.isFinal || method.isStatic)
        }
    }

}
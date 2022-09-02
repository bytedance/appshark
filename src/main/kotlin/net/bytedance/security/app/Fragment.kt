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

import net.bytedance.security.app.android.AndroidUtils
import net.bytedance.security.app.android.AndroidUtils.findFragmentsInLayout
import net.bytedance.security.app.android.LifecycleConst
import net.bytedance.security.app.preprocess.Patch.resolveMethodException
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.Value
import soot.jimple.*
import soot.jimple.internal.JAssignStmt
import soot.jimple.internal.JCastExpr
import soot.jimple.internal.JimpleLocal

/**
1. Find the Fragment in the Layout file and associate it with the Activity
2. Find the Fragment that is dynamically added in the code, generate the calling code, and inject it into the related Activity code.
 */
class Fragment(val ctx: PreAnalyzeContext) {
    private val androidFragmentClassName = "androidx.fragment.app.Fragment"

    /*
    key: subclass of androidx.fragment.app.Fragment
    value: callback method
     */
    var fragmentClassName2GeneratedEntry: MutableMap<String, SootMethod> = HashMap()

    var reachableDepth = 10
    fun findFragmentAndAddCallbackToEntry(entry: SootMethod) {
        fragmentClassName2GeneratedEntry.clear()
        val foundFragmentClass: MutableSet<SootClass> = HashSet()
        val layoutFragments = findFragmentByLayoutFile(entry)
        if (layoutFragments != null) {
            foundFragmentClass.addAll(layoutFragments)
        }
        lookupReferencedFragmentClassForOneEntry(entry, foundFragmentClass)
        callFragmentEntryMethod(entry)
    }

    private fun callFragmentEntryMethod(entry: SootMethod) {
        val units = entry.activeBody.units
        units.removeLast()
        for (m in fragmentClassName2GeneratedEntry.values) {
            val argType = m.getParameterType(0)
            val args: MutableList<Value> = ArrayList()
            val localArg = Jimple.v().newLocal("v0", argType)
            args.add(localArg)
            val invokeStmt = Jimple.v().newInvokeStmt(
                Jimple.v().newStaticInvokeExpr(
                    m.makeRef(), args
                )
            )
            units.add(invokeStmt)
        }
        // insert "return"
        units.add(Jimple.v().newReturnVoidStmt())
    }


    private fun lookupReferencedFragmentClassForOneEntry(
        entry: SootMethod,
        foundFragmentClass: MutableSet<SootClass>
    ): Set<SootClass> {
        val visited: MutableSet<SootMethod> = HashSet()
        queryFragmentByEntryRecursive(entry, reachableDepth, visited, foundFragmentClass)
        if (foundFragmentClass.isNotEmpty()) {
            addFragmentDynamic(foundFragmentClass, HashSet(foundFragmentClass), visited)
        }
        return foundFragmentClass
    }

    private fun setSootClass2SetString(s: Set<SootClass>): MutableSet<String> {
        val r: MutableSet<String> = HashSet()
        for (clz in s) {
            r.add(clz.name)
        }
        return r
    }


    private fun addNewFoundFragmentClassesToTotal(
        totalFragmentSet: MutableSet<SootClass>,
        newClasses: Set<SootClass>
    ): Set<SootClass> {
        val filtered: MutableSet<SootClass> = HashSet()
        if (newClasses.isEmpty()) {
            return filtered
        }
        val totalStrings: Set<String> = setSootClass2SetString(totalFragmentSet)
        val newStrings = setSootClass2SetString(newClasses)
        newStrings.removeAll(totalStrings)
        if (newStrings.isNotEmpty()) {
            for (clz in newClasses) {
                for (s in newStrings) {
                    if (clz.name == s) {
                        totalFragmentSet.add(clz)
                        filtered.add(clz)
                    }
                }
            }
        }
        return filtered
    }


    private fun addFragmentDynamic(
        totalFragmentSet: MutableSet<SootClass>,
        currentFragmentSet: Set<SootClass>,
        visited: MutableSet<SootMethod>
    ) {
        val filteredNewClasses: MutableSet<SootClass> = HashSet()
        for (fragmentClass in currentFragmentSet) {
            val fragmentEntry =
                PLUtils.createComponentEntry(androidFragmentClass, fragmentClass, LifecycleConst.FragmentMethods)
            fragmentClassName2GeneratedEntry[fragmentClass.name] = fragmentEntry

            val newClasses: MutableSet<SootClass> = HashSet()
            queryFragmentByEntryRecursive(fragmentEntry, reachableDepth, visited, newClasses)
            filteredNewClasses.addAll(addNewFoundFragmentClassesToTotal(totalFragmentSet, newClasses))
        }
        if (filteredNewClasses.isNotEmpty()) {
            addFragmentDynamic(totalFragmentSet, filteredNewClasses, visited)
        }
    }

    private fun queryFragmentByEntryRecursive(
        entry: SootMethod,
        depth: Int,
        visited: MutableSet<SootMethod>,
        visitedFragmentClass: MutableSet<SootClass>
    ) {
        if (depth <= 0) {
            return
        }
        if (visited.contains(entry)) {
            return
        }
        visited.add(entry)
        val callees = ctx.callGraph.heirCallGraph[entry] ?: return
        val methods = HashSet(fragmentTransactionMethods.keys)
        methods.retainAll(callees)
        if (methods.isNotEmpty()) {
            for (unit in entry.activeBody.units) {
                val stmt = unit as Stmt
                if (stmt.containsInvokeExpr()) {
                    val invokeExpr = stmt.invokeExpr
                    var value: Value?
                    val i = fragmentTransactionMethods[resolveMethodException(invokeExpr)] ?: continue
                    value = invokeExpr.args[i]
                    val clz = Scene.v().getSootClassUnsafe(value.type.toString(), false)
                    if (androidFragmentClassName == clz.name) {
                        val s = findOneStepFragment(entry, value as JimpleLocal)
                        visitedFragmentClass.addAll(s)
                        continue
                    }
                    addFragmentSootClassToSet(visitedFragmentClass, clz)
                }
            }
        }
        for (methodSignature in callees) {
            queryFragmentByEntryRecursive(methodSignature, depth - 1, visited, visitedFragmentClass)
        }
    }


    private fun findOneStepFragment(m: SootMethod, fragmentLocal: JimpleLocal): Set<SootClass> {
        val classes: MutableSet<SootClass> = HashSet()
        for (unit in m.activeBody.units) {
            val stmt = unit as Stmt
            if (stmt is JAssignStmt) {
                if (stmt.leftOp !is JimpleLocal) {
                    continue
                }
                val leftExpr = stmt.leftOp as JimpleLocal
                val rightExpr = stmt.rightOp
                if (leftExpr.name !== fragmentLocal.name) {
                    continue
                }
                var c: SootClass? = null

                // r7_4 = r3;r7_4=$r1;
                if (rightExpr is JimpleLocal) {
                    c = Scene.v().getSootClassUnsafe(rightExpr.type.toString(), false)

                } else if (rightExpr is InvokeExpr) {
                    c = Scene.v()
                        .getSootClassUnsafe(resolveMethodException(rightExpr).returnType.toString(), false)

                } else if (rightExpr is JCastExpr) {
                    c = Scene.v().getSootClassUnsafe(rightExpr.op.type.toString(), false)

                    if (c.isInterface) {
                        continue
                    }
                } else if (rightExpr is FieldRef) {
                    c = Scene.v().getSootClassUnsafe(rightExpr.field.type.toString(), false)

                }

                if (c != null && Scene.v().orMakeFastHierarchy.isSubclass(c, androidFragmentClass)) {
                    addFragmentSootClassToSet(classes, c)
                }
            }
        }
        return classes
    }

    private fun addFragmentSootClassToSet(s: MutableSet<SootClass>, c: SootClass) {
        if (androidFragmentClassName == c.name) {
            return
        }
        for (clz in s) {
            if (clz.name === c.name) {
                return
            }
        }
        val subClassSet = HashSet<SootClass>()
        PLUtils.getAllSubCLass(c, subClassSet)
        s.addAll(subClassSet)
        s.add(c)
    }

    private fun findFragmentByLayoutFile(m: SootMethod): Set<SootClass>? {
        val layoutId = findLayoutId(m)
        return if (layoutId < 0) {
            null
        } else findFragmentsInLayout(layoutId)

    }


    private fun findLayoutId(entry: SootMethod): Int {
        val visited: MutableSet<String> = HashSet()
        return queryLayoutIdRecursive(entry, 4, visited)
    }

    private fun queryLayoutIdRecursive(
        entry: SootMethod,
        depth: Int,
        visited: MutableSet<String>
    ): Int {
        if (depth <= 0) {
            return -1
        }
        if (visited.contains(entry.signature)) {
            return -1
        }
        visited.add(entry.signature)
        val callees = ctx.callGraph.heirCallGraph[entry] ?: return -1
        if (!callees.contains(compatActivitySetContentView)) {
            for (m in callees) {
                val id = queryLayoutIdRecursive(m, depth - 1, visited)
                if (id > 0) {
                    return id
                }
            }
        }
        for (unit in entry.activeBody.units) {
            val stmt = unit as Stmt
            if (stmt.containsInvokeExpr()) {
                val invokeExpr = stmt.invokeExpr
                if (compatActivitySetContentView.signature != resolveMethodException(invokeExpr).signature) {
                    continue
                }
                val value = invokeExpr.args[0]
                if (value is IntConstant) {
                    return value.value
                }
            }
        }
        return -1
    }

    companion object {
        fun processFragmentEntries(ctx: PreAnalyzeContext) {
            val start = System.currentTimeMillis()
            val f = Fragment(ctx)
            for ((_, fakeEntry) in AndroidUtils.activityEntryMap) {
                f.findFragmentAndAddCallbackToEntry(fakeEntry)
            }
            Log.logDebug("processFragmentEntries takes time " + (System.currentTimeMillis() - start) + "ms")
        }


    }

    private val compatActivitySetContentView: SootMethod =
        Scene.v().grabMethod("<androidx.appcompat.app.AppCompatActivity: void setContentView(int)>")

    var fragmentTransactionMethods: HashMap<SootMethod, Int> = HashMap()


    private var androidFragmentClass: SootClass = Scene.v().getSootClassUnsafe("androidx.fragment.app.Fragment", false)

    init {
        mapOf(
            "<androidx.fragment.app.FragmentTransaction: androidx.fragment.app.FragmentTransaction replace(int,androidx.fragment.app.Fragment)>" to 1,
            "<androidx.fragment.app.FragmentTransaction: androidx.fragment.app.FragmentTransaction replace(int,androidx.fragment.app.Fragment,java.lang.String)>" to 1,
            "<androidx.fragment.app.FragmentTransaction: androidx.fragment.app.FragmentTransaction add(androidx.fragment.app.Fragment,java.lang.String)>" to 0,
            "<androidx.fragment.app.FragmentTransaction: androidx.fragment.app.FragmentTransaction add(int,androidx.fragment.app.Fragment)>" to 1,
            "<androidx.fragment.app.FragmentTransaction: androidx.fragment.app.FragmentTransaction add(int,androidx.fragment.app.Fragment,java.lang.String)>" to 1,
        ).forEach {
            val method = Scene.v().grabMethod(it.key)
            fragmentTransactionMethods[method] = it.value
        }
    }
}

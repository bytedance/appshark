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

import net.bytedance.security.app.preprocess.*
import net.bytedance.security.app.rules.IRulesForContext
import net.bytedance.security.app.util.profiler
import soot.Scene
import soot.SootClass
import soot.SootField
import soot.SootMethod
import java.util.concurrent.atomic.AtomicInteger

/**
 * for jsb methods
 */
interface ContextWithJSBMethods {
    fun getJSBMethods(): List<SootMethod>
}

/**
 * The context before the pointer analysis ,it contains all the preprocessing information for the Java program.
 */

open class PreAnalyzeContext {

    /**
     * key is the function that is callee,value is the caller functions and the statement that occurs
     * Direct is the function that is called directly without considering CHA relationship
     * Heir is after considering CHA
     */
    val methodDirectRefs: MutableMap<SootMethod, MutableSet<CallSite>> = HashMap()

    /**
     * Key is the field to be loaded, and value is the callsite
     * for example a=b.c;
     */
    val loadFieldRefs: MutableMap<SootField, MutableSet<CallSite>> = HashMap()

    /**
     *Key is the field to be stored, and value is the callSite
     * for example a.b=c;
     */
    val storeFieldRefs: MutableMap<SootField, MutableSet<CallSite>> = HashMap()

    /**
    key is the pattern in the rule, and value is the place where possible matching constant strings appear
     */
    var constStringPatternMap: MutableMap<String, MutableSet<CallSite>> = HashMap()


    val newInstanceRefs: MutableMap<SootClass, MutableSet<CallSite>> = HashMap()


    val callGraph = CallGraph()


    private var classCounter: AtomicInteger = AtomicInteger(0)
    private var methodsCounter: AtomicInteger = AtomicInteger(0)


    fun addMethodCounter(): Int {
        return methodsCounter.incrementAndGet()
    }

    fun addClassCounter(): Int {
        return classCounter.incrementAndGet()
    }

    fun getMethodCounter(): Int {
        return methodsCounter.get()
    }

    fun getClassCounter(): Int {
        return classCounter.get()
    }

    suspend fun createContext(
        rules: IRulesForContext,
        callBackEnhance: Boolean
    ) {
        val cam = createClassAndMethodHandler(this)
        addClassAndMethodVisitor(cam, rules, callBackEnhance)
        cam.run()
        profiler.initProcessMethodStatistics(getMethodCounter(), getClassCounter(), this)
    }

    fun buildCustomClassCallGraph(rules: IRulesForContext) {
        val cam = createClassAndMethodHandler(this)
        addClassAndMethodVisitor(cam, rules, false)
        cam.buildCustomClassCallGraph()
    }

    private fun createClassAndMethodHandler(ctx: PreAnalyzeContext): AnalyzePreProcessor {
        return AnalyzePreProcessor(getConfig().getMaxPreprocessorThread(), ctx)
    }

    protected open fun addClassAndMethodVisitor(
        cam: AnalyzePreProcessor, rules: IRulesForContext,
        callBackEnhance: Boolean
    ) {

//        val constStrPatternInRules = MethodFieldConstCacheVisitor.parseAllConstStrPatternInRules(ruleDir, ruleList)
        cam.addMethodVisitor {
            //1. ssa Make sure SSA is at the first
            MethodVisitorStatistics(MethodSSAVisitor())
        }.addMethodVisitor {
            //2. The callback must be handled after the SSA, otherwise the function doesn't have body
            MethodVisitorStatistics(MethodCallbackVisitor(callBackEnhance))
        }.addMethodVisitor {
            //3.  MethodFieldConstCacheVisitor must be handled after ssa, because there are dependencies
            MethodFieldConstCacheVisitor(
                this,
                MethodStmtFieldCache(),
                rules.constStringPatterns(),
                rules.fields(),
                rules.newInstances()
            )
        }.addMethodVisitor {
            MethodCounter(this)
        }
        cam.addClassVisitor { ClassCounter(this) }
    }

    @Suppress("unused", "unused")
    fun queryAMethod(method: SootMethod, result: MutableMap<SootMethod, Set<SootMethod>>, depth: Int) {
        if (depth <= 0) {
            return
        }
        if (result.containsKey(method)) {
            return
        }
        if (callGraph.heirReverseCallGraph.containsKey(method)) {
            result[method] = callGraph.heirReverseCallGraph[method]!!
            for (m in callGraph.heirReverseCallGraph[method]!!) {
                queryAMethod(m, result, depth - 1)
            }
        }
    }


    @Suppress("unused")
    fun findInvokeCallSite(methodSig: String): Set<CallSite> {
        val m = Scene.v().getMethod(methodSig)
        return findInvokeCallSite(m)
    }

    fun findInvokeCallSite(method: SootMethod): Set<CallSite> {
        return this.methodDirectRefs[method] ?: setOf()
    }

    fun findConstStringPatternCallSite(patternStr: String): Set<CallSite> {
        return this.constStringPatternMap[patternStr] ?: setOf()
    }

    fun findInstantCallSite(className: String): Set<CallSite> {
        val clz = Scene.v().getSootClassUnsafe(className) ?: return emptySet()
        return findInstantCallSite(clz)
    }

    fun findInstantCallSite(clz: SootClass): Set<CallSite> {
        return this.newInstanceRefs[clz] ?: setOf()
    }

    fun findInstantCallSiteWithSubclass(className: String): Set<CallSite> {
        val s = HashSet<CallSite>()
        for (sc in PLUtils.classes) {
            if (sc.name == className || sc.hasSuperclass() && className == sc.superclass.name) {
                s.addAll(findInstantCallSite(sc))
            }
        }
        return s
    }


    /**
     * field load callsites
     */
    fun findFieldCallSite(field: String): Set<CallSite> {
        val fields = MethodFinder.checkAndParseFieldSignature(field)
        val results = HashSet<CallSite>()
        for (f in fields) {
            results.addAll(findFieldCallSite(f))
        }
        return results
    }

    /**
     * field load callsites
     */
    fun findFieldCallSite(field: SootField): Set<CallSite> {
        return this.loadFieldRefs[field] ?: setOf()
    }
}
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
import net.bytedance.security.app.android.LifecycleConst
import net.bytedance.security.app.engineconfig.EngineConfig
import net.bytedance.security.app.engineconfig.isLibraryClass
import soot.SootClass
import soot.SootMethod
import java.util.*

/**
 * method call relations of all the app except library classes.
 */
class CallGraph {
    //  key is a caller method, value are all the direct callees of this method.
    var directCallGraph: MutableMap<SootMethod, MutableSet<SootMethod>> = HashMap()

    // key: a caller method value are all the direct callees of this method,
    // consider all possible inheritance functions in terms of CHA relations
    var heirCallGraph: MutableMap<SootMethod, MutableSet<SootMethod>> = HashMap()

    // key:a callee method,value: all the direct callers of this method
    var directReverseCallGraph: MutableMap<SootMethod, MutableSet<SootMethod>> = HashMap()

    // key: a callee method value are all the direct callers of this method,
    // consider all possible inheritance functions in terms of CHA relations
    var heirReverseCallGraph: MutableMap<SootMethod, MutableSet<SootMethod>> = HashMap()


    private val traceCache: MutableMap<String, CrossResult?> = HashMap()

    fun clear() {
        traceCache.clear()
    }


    private fun addToCallGraph(caller: SootMethod, callee: SootMethod, isDirect: Boolean) {
        if (EngineConfig.libraryConfig.isLibraryMethod(caller.signature)) {
            return
        }
        if (isDirect) {
            val calleeSet = directCallGraph.computeIfAbsent(caller) {
                HashSet()
            }
            calleeSet.add(callee)
            val callerSet = directReverseCallGraph.computeIfAbsent(callee) { HashSet() }
            callerSet.add(caller)
        }
        val calleeSet = heirCallGraph.computeIfAbsent(caller) { HashSet() }
        calleeSet.add(callee)
        val callerSet = heirReverseCallGraph.computeIfAbsent(callee) { HashSet() }
        callerSet.add(caller)
    }

    /**
     * user method may have an empty body
     */
    fun isUserCode(method: SootMethod): Boolean {
        return !isLibraryClass(method.declaringClass.name)
    }


    fun addEdge(caller: SootMethod, callee: SootMethod, isDirect: Boolean) {
        addToCallGraph(caller, callee, isDirect)
    }


    /*
        which functions are called by entry at a given depth
     */
    fun getAllCallees(entry: SootMethod, depth: Int): Set<SootMethod> {
        val s = HashSet<SootMethod>()
        query2Internal(entry, depth, s)
        return s
    }

    fun query2Internal(entry: SootMethod, depth: Int, s: HashSet<SootMethod>) {
        if (depth == 0) {
            return
        }
        if (s.contains(entry)) {
            return
        }
        s.add(entry)

        this.directCallGraph[entry]?.let {
            for (m in it) {
                query2Internal(m, depth - 1, s)
            }
        }
        this.heirCallGraph[entry]?.let {
            for (m in it) {
                query2Internal(m, depth - 1, s)
            }
        }
    }

    @Suppress("unused")
    fun debugGetCalleesGraph(entry: SootMethod, depth: Int): Map<String, Set<String>> {
        val s = HashMap<String, Set<String>>()
        debugGetCalleesGraphInternal(entry, depth, s)
        return s
    }

    fun debugGetCalleesGraphInternal(entry: SootMethod, depth: Int, s: HashMap<String, Set<String>>) {
        if (depth == 0) {
            return
        }
        if (s.contains(entry.signature)) {
            return
        }
        val cur = HashSet<SootMethod>()

        this.directCallGraph[entry]?.let {
            cur.addAll(it)
        }
        this.heirCallGraph[entry]?.let {
            cur.addAll(it)
        }
        s[entry.signature] = cur.map { it.signature }.toSet()
        for (m in cur) {
            debugGetCalleesGraphInternal(m, depth - 1, s)
        }
    }

    fun queryTopEntry(
        isPoly: Boolean,
        callee: SootMethod,
        depth: Int,
        entrySet: MutableSet<SootMethod>,
        isPrintLog: Boolean = false
    ) {
        if (isPoly) {
            queryTopEntryHeir(callee, depth, entrySet)
        } else {
            queryTopEntryDirect(callee, depth, entrySet, isPrintLog)
        }
    }


    fun queryTopEntryNoCustomMain(isPoly: Boolean, callee: SootMethod, depth: Int, entrySet: MutableSet<SootMethod>) {
        if (isPoly) {
            queryTopEntryHeirNoCustomMain(callee, depth, entrySet)
        } else {
            queryTopEntryDirectNoCustomMain(callee, depth, entrySet)
        }
    }

    /**
    Find all call paths from topEntry to sink
     */
    fun queryPath(topEntry: SootMethod, sink: SootMethod, depth: Int): MutableList<SootMethod> {
        val path: MutableList<SootMethod> = ArrayList()
        queryPathDirect(Stack(), topEntry, sink, path, depth)
        return path
    }

    private fun queryTopEntryDirect(
        callee: SootMethod,
        depth: Int,
        entrySet: MutableSet<SootMethod>,
        isPrintLog: Boolean
    ) {
        if (depth == 0) {
            entrySet.add(callee)
            return
        }
        if (!directReverseCallGraph.containsKey(callee)) {
            entrySet.add(callee)
            return
        }
        if (isPrintLog) {
            Log.logInfo("depth=$depth,nextCallee=${directReverseCallGraph[callee]}")
        }
        for (nextCallee in directReverseCallGraph[callee]!!) {
            queryTopEntryDirect(nextCallee, depth - 1, entrySet, isPrintLog)
        }
    }

    private fun queryTopEntryDirectNoCustomMain(
        callee: SootMethod,
        depth2: Int,
        entrySet: MutableSet<SootMethod>,
    ) {
        var depth = depth2
        if (entrySet.contains(callee)) {
            return
        }
        if (depth == 0) {
            entrySet.add(callee)
            return
        }
        if (!directReverseCallGraph.containsKey(callee)) {
            entrySet.add(callee)
            return
        }
        depth--
        for (nextCallee in directReverseCallGraph[callee]!!) {
            if (nextCallee.signature.contains(PLUtils.CUSTOM_METHOD)) {
                entrySet.add(callee)
                continue
            }
            queryTopEntryDirectNoCustomMain(nextCallee, depth, entrySet)
        }
    }

    /**
    Find all call paths from topEntry to sink
     */
    private fun queryPathDirect(
        stack: Stack<SootMethod>,
        topEntry: SootMethod,
        sink: SootMethod,
        path: MutableList<SootMethod>,
        maxDepth: Int
    ) {
        if (path.isNotEmpty()) {
            stack.push(sink)
            return
        }
        if (topEntry == sink) {
            stack.push(topEntry)
            path.addAll(stack)
            return
        }
        if (stack.contains(topEntry)) {
            stack.push(topEntry)
            return
        }
        if (stack.size > maxDepth) {
            stack.push(topEntry)
            return
        }
        if (!directCallGraph.containsKey(topEntry)) {
            stack.push(topEntry)
            return
        }
        stack.push(topEntry)
        for (nextTop in directCallGraph[topEntry]!!) {
            queryPathDirect(stack, nextTop, sink, path, maxDepth)
            stack.pop()
        }
    }

    /**
     * Find the top function that calls callee indirectly,
     * for example: f1->f2-> F3 ->f4->callee
     * Unless the depth limit is reached or the method doesn't have any caller.
     */
    private fun queryTopEntryHeir(callee: SootMethod, depth: Int, entrySet: MutableSet<SootMethod>) {
        if (depth == 0) {
            entrySet.add(callee)
            return
        }
        if (!heirReverseCallGraph.containsKey(callee)) {
            entrySet.add(callee)
            return
        }
        for (nextCallee in heirReverseCallGraph[callee]!!) {
            queryTopEntryHeir(nextCallee, depth - 1, entrySet)
        }
    }

    private fun queryTopEntryHeirNoCustomMain(
        callee: SootMethod,
        depth: Int,
        entrySet: MutableSet<SootMethod>,
    ) {
        if (entrySet.contains(callee)) {
            return
        }
        if (depth == 0) {
            entrySet.add(callee)
            return
        }
        if (!heirReverseCallGraph.containsKey(callee)) {
            entrySet.add(callee)
            return
        }
        for (nextCallee in heirReverseCallGraph[callee]!!) {
            if (nextCallee.signature.contains(PLUtils.CUSTOM_METHOD)) {
                entrySet.add(callee)
                continue
            }
            queryTopEntryHeirNoCustomMain(nextCallee, depth - 1, entrySet)
        }
    }


    /**
     * find the first method which is the caller of sourceSig and sink,if there doesn't exist such caller,return null.
     * @param polymorphism include polymorphism method or not
     * @param source   the source method
     * @param sink     the sink method
     * @param depth     max depth to search
     * @return the caller to find
     */
    fun traceAndCross(polymorphism: Boolean, source: SootMethod, sink: SootMethod, depth: Int): CrossResult? {
        val cacheKey = source.signature + sink.signature + depth
        synchronized(this) {
            if (traceCache.containsKey(cacheKey)) {
                return traceCache[cacheKey]
            }
        }
        val ssc = SourceAndSinkCross(polymorphism, source, sink, depth, false, this)
        val s = ssc.traceAndCross()
        synchronized(this) {
            traceCache[cacheKey] = s
        }
        return s
    }


    /**
    top method is a method doesn't have a caller.
    @return key is the class, value is the methods of this class that don't have a caller.
     */
    fun getTopMethods(): Map<SootClass, Set<SootMethod>> {
        val r = HashMap<SootClass, MutableSet<SootMethod>>()
        for ((caller, _) in this.heirCallGraph) {
            if (this.heirReverseCallGraph.containsKey(caller)) {
                continue
            }
            val c = caller.declaringClass
            //skip android component
            if (LifecycleConst.isComponentClass(c)) {
                continue
            }
            //skip library
            if (EngineConfig.libraryConfig.isLibraryClass(c.name)) {
                continue
            }
            if (c.name.contains("$")) {
                continue //skip internal class, because it's patched by MethodCallbackVisitor
            }
            var s = r[c]
            if (s == null) {
                s = HashSet()
                r[c] = s
            }
            s.add(caller)
        }
        return r
    }

    data class CrossResult(val entryMethod: SootMethod, val depth: Int)

    /**
     * find a method where it's caller of src and caller of sink
    algorithm:
    if A represents the src, and B represents the sink
    1. S1=\[A\], S2=\[B\]
    2. if intersection of S1 and S2 is not empty, return the first method in the intersection
    3.  add all the direct caller2 of A to S1, S1=[A,A11,A12,A13],
    and add all the direct callers of B to  S2, S2=[B,B11,B12,B13]
    4. go back to step 2
     */
    class SourceAndSinkCross(
        poly: Boolean,
        val src: SootMethod,
        val sink: SootMethod,
        var depth: Int,
        private val isPrintLog: Boolean = false,
        cg: CallGraph
    ) {
        val sourceSet = mutableSetOf(src)
        val sinkSet = mutableSetOf(sink)
        var srcNewSet = setOf(src)
        var sinkNewSet = setOf(sink)
        val queryMap: Map<SootMethod, Set<SootMethod>>
        var result: CrossResult? = null
        var resultMethod: SootMethod? = null

        init {
            if (poly) {
                queryMap = cg.heirReverseCallGraph
            } else {
                queryMap = cg.directReverseCallGraph
            }
        }

        fun traceAndCross(): CrossResult? {
            crossInternal()
            if (resultMethod != null) {
                return CrossResult(resultMethod!!, depth)
            }
            return null
        }

        /**
         *  don't use retainAll to avoid HashSet allocation
         */
        private fun cross(s1: Set<SootMethod>, s2: Set<SootMethod>): SootMethod? {
            for (a in s1) {
                if (s2.contains(a)) {
                    return a
                }
            }
            return null
        }

        private fun crossInternal() {
            while (true) {
                if (depth == 0) {
                    return
                }
                resultMethod = cross(sourceSet, sinkSet)
                if (resultMethod != null) {
                    return
                }
                val srcNewSet2 = HashSet<SootMethod>()
                val sinkNewSet2 = HashSet<SootMethod>()
                for (s in srcNewSet) {
                    queryMap[s]?.let { srcNewSet2.addAll(it) }
                }
                for (s in sinkNewSet) {
                    queryMap[s]?.let { sinkNewSet2.addAll(it) }
                }
                if (srcNewSet2.isEmpty() && sinkNewSet2.isEmpty()) {
                    return
                }
                sourceSet.addAll(srcNewSet2)
                sinkSet.addAll(sinkNewSet2)
                srcNewSet = srcNewSet2
                sinkNewSet = sinkNewSet2
                if (isPrintLog) {
                    Log.logInfo("depth=$depth,srcNewSet=$srcNewSet")
                    Log.logInfo("sinkNewSet=$sinkNewSet")
                }
                depth -= 1
            }
        }
    }

    companion object {
        //for test only
        fun toStringMap(m: Map<SootMethod, Set<SootMethod>>): Map<String, Set<String>> {
            val dm: MutableMap<String, Set<String>> = HashMap()
            m.map { entry ->
                dm[entry.key.signature] = entry.value.map { it.signature }.toMutableSet()
            }
            return dm
        }
    }
}
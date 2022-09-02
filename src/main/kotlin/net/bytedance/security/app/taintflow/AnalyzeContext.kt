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

import net.bytedance.security.app.pointer.PLObject
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.pointer.PointerFactory
import net.bytedance.security.app.util.toFormatedString
import net.bytedance.security.app.util.toSortedMap
import soot.PrimType
import soot.SootMethod
import java.util.concurrent.ConcurrentHashMap


/**
 * the result of pointer analyze.
 */
class AnalyzeContext(val pt: PointerFactory) {
    // reachable methods
    var rm: MutableSet<SootMethod> = HashSet()

    // pointer to object set
    var pointerToObjectSet: MutableMap<PLPointer, MutableSet<PLObject>> = HashMap()

    /**
    specialinvoke $r0_1.<net.bytedance.security.app.bvaa.openConnection.A: void <init>(net.bytedance.security.app.bvaa.openConnection.A$1)>(null);
    <net.bytedance.security.app.bvaa.openConnection.A$innerA: net.bytedance.security.app.bvaa.openConnection.A ina> = $r0_1;
    key is r0_1,value:[<net.bytedance.security.app.bvaa.openConnection.A$innerA: net.bytedance.security.app.bvaa.openConnection.A ina>,
    <net.bytedance.security.app.bvaa.openConnection.A: void <init>(net.bytedance.security.app.bvaa.openConnection.A$1)>->@this]
    The key is the propagation source, and the value is the propagation destination
     */
    val variableFlowGraph: MutableMap<PLPointer, MutableSet<PLPointer>> = HashMap()

    /**
     * As with the variableFlowGraph, key is the propagation destination and value is the propagation source
     */
    private val reverseVariableFlowGraph: MutableMap<PLPointer, MutableSet<PLPointer>> = HashMap()

    /**
     *  $r0 = <net.bytedance.security.app.bvaa.openConnection.A$innerA: net.bytedance.security.app.bvaa.openConnection.A ina>;
     *  key is ina,value is r0, pointer propagated from ina to r0
     */
    var pointerFlowGraph: MutableMap<PLPointer, MutableSet<PLPointer>> = HashMap()

    fun dump(): String {
        return """
            ptrToSet={${pointerToObjectSet.toSortedMap().toFormatedString()}},
            
            
            ptrFlowGraph={${pointerFlowGraph.toSortedMap().toFormatedString()}},
            

            taintPtrFlowGraph={${variableFlowGraph.toSortedMap().toFormatedString()}},
        """.trimIndent()
    }

    fun baseInfo(): String {
        return """
            rm=${rm.size},
            pointerToObjectSet={${pointerToObjectSet.size}},
            pointerFlowGraph={${pointerFlowGraph.size}},
            taintPtrFlowGraph={${variableFlowGraph.size}},
            objects=${pt.objIndexMap.size},
            pointers=${pt.ptrIndexMap.size}
        """.trimIndent()
    }

    private fun addTaintPFGEdge(
        srcPtr: PLPointer,
        dstPtr: PLPointer,
        @Suppress("UNUSED_PARAMETER") isPrime: Boolean
    ): Boolean {
        addToPointFlowGraph(dstPtr, srcPtr, reverseVariableFlowGraph)
        return addToPointFlowGraph(srcPtr, dstPtr, variableFlowGraph)
    }

    /**
     * If srcPtr does not point to dstPtr, it is added to pointerFlowGraph and then returns true,
     * If srcPtr already points to dstPtr, return false
     */
    private fun addPtrFlowEdge(srcPtr: PLPointer, dstPtr: PLPointer): Boolean {
        return addToPointFlowGraph(srcPtr, dstPtr, pointerFlowGraph)
    }

    /**
     * If srcPtr does not point to dstPtr, it is added to pfg and then returns true,
     * If srcPtr already points to dstPtr, return false
     */
    private fun addToPointFlowGraph(
        srcPtr: PLPointer, dstPtr: PLPointer,
        pfg: MutableMap<PLPointer, MutableSet<PLPointer>>
    ): Boolean {
        var dstSet = pfg[srcPtr]
        if (dstSet == null) {
            dstSet = HashSet()
            pfg[srcPtr] = dstSet
        }
        if (!dstSet.contains(dstPtr)) {
            dstSet.add(dstPtr)
            return true
        }
        return false
    }

    fun getPointToSet(ptr: PLPointer): Set<PLObject>? {
        return pointerToObjectSet[ptr]
    }

    fun isInPointToSet(ptr: PLPointer): Boolean {
        return pointerToObjectSet.containsKey(ptr)
    }

    fun addToPointToSet(ptr: PLPointer, obj: PLObject) {
        val objSet = pointerToObjectSet.computeIfAbsent(ptr) { HashSet() }
        objSet.add(obj)
    }

    private fun addToPointToSet(ptr: PLPointer, objs: Set<PLObject>) {
        val objSet = pointerToObjectSet.computeIfAbsent(ptr) { HashSet() }
        objSet.addAll(objs)
    }

    private fun propagate(srcPtr: PLPointer, obj: PLObject) {
        val dstPointers = pointerFlowGraph[srcPtr]
        if (dstPointers != null) {
            for (dstPtr in dstPointers) {
                var dstObjects = pointerToObjectSet[dstPtr]
                if (dstObjects == null) {
                    dstObjects = HashSet()
                    pointerToObjectSet[dstPtr] = dstObjects
                    dstObjects.add(obj)
                } else {
                    if (!dstObjects.contains(obj)) {
                        dstObjects.add(obj)
                        propagate(dstPtr, obj)
                    }
                }
            }
        }
    }


    private fun propagate(srcPtr: PLPointer, objs: Set<PLObject>) {
        val dstPtrs = pointerFlowGraph[srcPtr] ?: return
        for (dstPtr in dstPtrs) {
            var dstObjs = pointerToObjectSet[dstPtr]
            if (dstObjs == null) {
                dstObjs = HashSet()
                pointerToObjectSet[dstPtr] = dstObjs
                dstObjs.addAll(objs)
                propagate(dstPtr, objs)
            } else {
                for (obj in objs) {
                    if (!dstObjs.contains(obj)) {
                        dstObjs.addAll(objs)
                        propagate(dstPtr, objs)
                        break
                    }
                }
            }
        }

    }

    private fun propagateObjs(srcPtr: PLPointer, dstPtr: PLPointer) {
        val objs = pointerToObjectSet[srcPtr]
        if (objs == null || objs.isEmpty()) {
            return
        }
        addToPointToSet(dstPtr, objs)

        propagate(dstPtr, objs)
    }


    private fun propagateObj(srcPtr: PLPointer, obj: PLObject) {
        propagate(srcPtr, obj)
    }

    /**
     * Add an edge to the pointerFlowGraph and propagate it if isPointerNeedPropagate is true.
     * add an edge to the variableFlowGraph
     * @param isPointerNeedPropagate  indicating that the pointer relationship needs to be propagated
     */

    fun addPtrEdge(srcPtr: PLPointer, dstPtr: PLPointer, isPointerNeedPropagate: Boolean = true) {
        addVariableFlowEdge(srcPtr, dstPtr)
        if (addPtrFlowEdge(srcPtr, dstPtr)) {
            if (isPointerNeedPropagate) {
                propagateObjs(srcPtr, dstPtr)
            }
        }
    }


    fun addVariableFlowEdge(srcPtr: PLPointer, dstPtr: PLPointer, isPrime: Boolean) {
        addTaintPFGEdge(srcPtr, dstPtr, isPrime)
    }

    fun addVariableFlowEdge(srcPtr: PLPointer, dstPtr: PLPointer) {
        if (isPrimePtr(srcPtr) || isPrimePtr(dstPtr)) {
            addVariableFlowEdge(srcPtr, dstPtr, true)
        } else {
            addVariableFlowEdge(srcPtr, dstPtr, false)
        }
    }


    fun addObjToPTS(srcPtr: PLPointer, obj: PLObject) {
        addToPointToSet(srcPtr, obj)
        propagateObj(srcPtr, obj)
    }


    private val propagationCache = ConcurrentHashMap<String, Set<PLPointer>>()


    fun collectPropagation(
        src: PLPointer,
        isIncludePrimeTaint: Boolean = false
    ): Set<PLPointer> {
        val key = "${src.signature()}:$isIncludePrimeTaint:0"
        propagationCache[key]?.let {
            return it
        }
        val s = collectPropagationInternal(src, this.variableFlowGraph, isIncludePrimeTaint)
        propagationCache[key] = s
        return s
    }

    fun collectReversePropagation(
        dst: PLPointer,
        isIncludePrimeTaint: Boolean = false
    ): Set<PLPointer> {
        val key = "${dst.signature()}:$isIncludePrimeTaint}:1"
        propagationCache[key]?.let {
            return it
        }
        val s = collectPropagationInternal(dst, this.reverseVariableFlowGraph, isIncludePrimeTaint)
        propagationCache[key] = s
        return s
    }

    private fun collectPropagationInternal(
        src: PLPointer,
        graph: Map<PLPointer, Set<PLPointer>>,
        isIncludePrimeTaint: Boolean = false
    ): Set<PLPointer> {
        val result = HashSet<PLPointer>()
        val next = ArrayList<PLPointer>()
        next.add(src)
        while (next.isNotEmpty()) {
            val p = next.removeLast()
            if (result.contains(p)) {
                continue
            }
            result.add(p)
            graph[p]?.let { candidates ->
                for (n in candidates) {
                    if (result.contains(n)) {
                        continue
                    }
                    if (!isIncludePrimeTaint && (isPrimePtr(p) || isPrimePtr(n))) {
                        continue
                    }
                    next.add(n)
                }
            }
        }
        return result
    }

    companion object {
        fun isPrimePtr(ptr: PLPointer): Boolean {
            return ptr.ptrType is PrimType
        }
    }
}
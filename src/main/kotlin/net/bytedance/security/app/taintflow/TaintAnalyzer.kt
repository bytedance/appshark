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

import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.util.profiler
import soot.SootMethod
import soot.Type
import soot.jimple.Stmt

/**
TaintAnalyzerData represents  the parsed  source and sink in Rule.
 */
class TaintAnalyzerData {


    /**
     *key is the PLLocalPointer's name, value is the PLLocalPointer.
     * it contains all sources and sinks
     */

    var pointerIndexMap: MutableMap<String, PLPointer> = HashMap()

    // sources
    var sourcePointerSet: MutableSet<PLLocalPointer> = HashSet()

    var sinkPointerSet: MutableSet<PLLocalPointer> = HashSet()

    // the stmt which contains the sources and sinks
    var ptrStmtMapSrcSink: MutableMap<PLLocalPointer, MutableSet<Stmt>> = HashMap()


    private fun allocPtr(method: SootMethod, localName: String, origType: Type): PLLocalPointer {
        val ptrSig = PLLocalPointer.getLocalLongSignature(method, localName)
        if (pointerIndexMap.containsKey(ptrSig)) {
            return pointerIndexMap[ptrSig] as PLLocalPointer
        }
        val ptr = PLLocalPointer(method, localName, origType)
        pointerIndexMap[ptrSig] = ptr
        return ptr
    }

    fun allocSourcePtr(method: SootMethod, localName: String, origType: Type): PLLocalPointer {
        val ptr = allocPtr(method, localName, origType)
        sourcePointerSet.add(ptr)
        return ptr
    }

    private fun allocSinkPtr(method: SootMethod, localName: String, origType: Type): PLLocalPointer {
        val ptr = allocPtr(method, localName, origType)
        sinkPointerSet.add(ptr)
        return ptr
    }


    fun allocPtrWithStmt(
        stmt: Stmt,
        method: SootMethod,
        localName: String,
        origType: Type,
        isSource: Boolean
    ): PLLocalPointer {
        val ptr = if (isSource) allocSourcePtr(method, localName, origType)
        else {
            allocSinkPtr(method, localName, origType)
        }
        if (!ptrStmtMapSrcSink.containsKey(ptr)) {
            ptrStmtMapSrcSink[ptr] = HashSet()
        }
        ptrStmtMapSrcSink[ptr]!!.add(stmt)
        return ptr
    }

}

class TaintAnalyzer {
    var data: TaintAnalyzerData = TaintAnalyzerData()
    val rule: TaintFlowRule
    val entryMethod: SootMethod

    //analyze depth for this analyzer
    val thisDepth: Int
    val sinkPtrSet get() = this.data.sinkPointerSet
    val sourcePtrSet get() = this.data.sourcePointerSet

    constructor(rule: TaintFlowRule, entryMethod: SootMethod) {
        this.rule = rule
        this.entryMethod = entryMethod
        this.thisDepth = rule.traceDepth
    }

    constructor(rule: TaintFlowRule, entryMethod: SootMethod, data: TaintAnalyzerData) {
        this.rule = rule
        this.entryMethod = entryMethod
        this.data = data
        this.thisDepth = rule.traceDepth
    }

    constructor(
        rule: TaintFlowRule,
        entryMethod: SootMethod,
        data: TaintAnalyzerData,
        srcPtr: PLLocalPointer,
        sinkPtr: PLLocalPointer,
        thisDepth: Int
    ) {
        this.rule = rule
        this.entryMethod = entryMethod
        this.data.sourcePointerSet.add(srcPtr)
        this.data.sinkPointerSet.add(sinkPtr)
        this.data.pointerIndexMap[srcPtr.signature()] = srcPtr
        this.data.pointerIndexMap[sinkPtr.signature()] = sinkPtr
        data.ptrStmtMapSrcSink[srcPtr]?.let {
            this.data.ptrStmtMapSrcSink[srcPtr] = it
        }
        data.ptrStmtMapSrcSink[sinkPtr]?.let {
            this.data.ptrStmtMapSrcSink[sinkPtr] = it
        }
        this.thisDepth = thisDepth
    }

    init {
        profiler.addTaintAnalyzerCount()
    }


    fun dump(): String {
        return """
           rule=${rule.name},
           EntryMethod=${entryMethod.signature},
           ptrIndexMap=${data.pointerIndexMap},
           sourcePtrSet=${data.sourcePointerSet},
           sinkPtrSet=${data.sinkPointerSet},
           ptrStmtMapSrcSink=${data.ptrStmtMapSrcSink}
        """.trimIndent()
    }

}
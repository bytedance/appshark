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

import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.pointer.PLLocalPointer
import soot.SootMethod

/**
 * skip methods has no relation with sinks and sources
 */
class PruneMethodAnalyzeMode(
    ctx: PreAnalyzeContext,
    pointers: List<PLLocalPointer>,
    depth: Int,
    private val defaultMethodAnalyzeMode: IMethodAnalyzeMode
) :
    IMethodAnalyzeMode {
    private val includedMethods: Set<SootMethod>

    init {
        this.includedMethods = buildIncludedMethods(ctx, pointers, depth)
    }


    override fun methodMode(method: SootMethod): MethodAnalyzeMode {
        if (!includedMethods.contains(method)) {
            return MethodAnalyzeMode.Obscure
        }
        return defaultMethodAnalyzeMode.methodMode(method)
    }

    companion object {
        private fun buildIncludedMethods(
            ctx: PreAnalyzeContext,
            pointers: List<PLLocalPointer>,
            depth: Int
        ): Set<SootMethod> {
            val result = HashSet<SootMethod>()
            pointers.forEach { queryCallers(ctx, it.method, depth, result) }

            return result
        }

        private fun queryCallers(
            ctx: PreAnalyzeContext,
            callee: SootMethod,
            depth: Int,
            result: MutableSet<SootMethod>
        ) {
            result.add(callee)
            if (depth == 0) {
                return
            }
            val nextCallers = ctx.callGraph.heirReverseCallGraph[callee] ?: return
            for (nextCaller in nextCallers) {
                if (result.contains(nextCaller)) {
                    return
                }
                queryCallers(ctx, nextCaller, depth - 1, result)
            }
        }

        //make sure all the analyzers have the same rule
        fun fromTaintAnalyzers(
            analyzers: List<TaintAnalyzer>,
            depth: Int,
            ctx: PreAnalyzeContext
        ): PruneMethodAnalyzeMode {
            val pointers = HashSet<PLLocalPointer>()
            analyzers.forEach {
                pointers.addAll(it.sinkPtrSet)
                pointers.addAll(it.sourcePtrSet)
            }
            return PruneMethodAnalyzeMode(ctx, pointers.toList(), depth, DefaultMethodAnalyzeMode)
        }
    }
}
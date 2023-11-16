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


package net.bytedance.security.app.ruleprocessor

import kotlinx.coroutines.*
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.getConfig
import net.bytedance.security.app.rules.DirectModeRule
import net.bytedance.security.app.rules.SliceModeRule
import net.bytedance.security.app.taintflow.TaintAnalyzer
import net.bytedance.security.app.util.oomHandler
import soot.SootMethod


class SliceModeProcessor(ctx: PreAnalyzeContext) : DirectModeProcessor(ctx) {

    override fun name(): String {
        return "SliceMode"
    }


    override suspend fun createAnalyzers(
        rule: DirectModeRule,
        taintRuleSourceSinkCollector: TaintRuleSourceSinkCollector,
        entries: List<SootMethod>,
        analyzers: MutableList<TaintAnalyzer>
    ) {
        assert(rule is SliceModeRule && rule.isSliceEnable)
        if (!getConfig().doWholeProcessMode) {
            createAnalyzersForSourceAndSink(taintRuleSourceSinkCollector, rule as SliceModeRule, analyzers)
        } else {
            super.createAnalyzers(rule, taintRuleSourceSinkCollector, entries, analyzers)
        }
    }

    suspend fun createAnalyzersForSourceAndSink(
        taintRuleSourceSinkCollector: TaintRuleSourceSinkCollector,
        rule: SliceModeRule,
        analyzers: MutableList<TaintAnalyzer>
    ) {
        val jobs = ArrayList<Job>()
        val scope = CoroutineScope(Dispatchers.Default)
        for (srcPtr in taintRuleSourceSinkCollector.analyzerData.sourcePointerSet) {
            //if srcPtr is a library method, it
            val callstacks = if (taintRuleSourceSinkCollector.parameterSources.contains(srcPtr)) {
                this.ctx.callGraph.getAllCallees(srcPtr.method, rule.traceDepth)
            } else {
                null
            }
            for (sinkPtr in taintRuleSourceSinkCollector.analyzerData.sinkPointerSet) {
                val job = scope.launch(CoroutineName("createAnalyzersForSourceAndSink-${rule.name}") + oomHandler) {

                    val entryItem = if (callstacks == null) {
                        val result = ctx.callGraph.traceAndCross(
                            rule.polymorphismBackTrace,
                            srcPtr.method,
                            sinkPtr.method,
                            rule.traceDepth - 1
                        ) ?: return@launch
                        /*
                         val thisDepth = rule.traceDepth - result.depth + 10
                         use thisDepth may lead to a lot of false negative,
                        The depth from traceMethod to source and sink can be very shallow, resulting in missing analysis of some key functions
                         */
                        Pair(result.entryMethod, rule.traceDepth)
                    } else {
                        if (!callstacks.contains(sinkPtr.method)) {
                            return@launch
                        }
                        Pair(srcPtr.method, rule.traceDepth)
                    }

                    val analyzer = TaintAnalyzer(
                        rule,
                        entryItem.first,
                        taintRuleSourceSinkCollector.analyzerData,
                        srcPtr,
                        sinkPtr,
                        entryItem.second
                    )
                    synchronized(analyzers) {
                        analyzers.add(analyzer)

                    }
                }
//                job.join() //for test only
                jobs.add(job)
            }
        }
        jobs.joinAll()
    }

}
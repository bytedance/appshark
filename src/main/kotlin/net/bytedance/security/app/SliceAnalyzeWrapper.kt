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

import net.bytedance.security.app.Log.logInfo
import net.bytedance.security.app.engineconfig.EngineConfig
import net.bytedance.security.app.pathfinder.TaintPathFinder
import net.bytedance.security.app.pointer.PointerFactory
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.taintflow.*
import net.bytedance.security.app.util.TaskQueue
import net.bytedance.security.app.util.profiler
import java.util.concurrent.atomic.AtomicInteger


data class AnalyzersAndDepth(
    val analyzers: ArrayList<TaintAnalyzer>,
    var depth: Int,
    val rule: TaintFlowRule,
    val name: String
)


class SliceAnalyzeWrapper(
    val ctx: PreAnalyzeContext,
    val analyzers: List<TaintAnalyzer>,
) {
    private fun groupAnalyzers(): Map<String, AnalyzersAndDepth> {
        val m = HashMap<String, AnalyzersAndDepth>()
        for (a in analyzers) {
            val name = "${a.entryMethod.signature}- ${a.rule.name}"
            val l =
                m.computeIfAbsent(name) {
                    AnalyzersAndDepth(
                        ArrayList(),
                        0,
                        a.rule,
                        name
                    )
                }
            l.analyzers.add(a)
            if (a.thisDepth > l.depth) {
                l.depth = a.thisDepth
            }
        }

        return m
    }


    suspend fun run() {
        val defaultPointerPropagationRule = DefaultPointerPropagationRule(EngineConfig.PointerPropagationConfig)
        val defaultVariableFlowRule = DefaultVariableFlowRule(EngineConfig.variableFlowConfig)
        val allTask = groupAnalyzers()
        val finishedTask = AtomicInteger(0)
        val analyzeTimeInSeconds =
            getConfig().maxPointerAnalyzeTime * 1000.toLong() / 3 * 2
        val q = TaskQueue<AnalyzersAndDepth>("SliceAnalyzeWrapper", getConfig().getMaxPointerAnalyzeThread()) { ad, _ ->
            val vfr = if (ad.rule.taintTweak != null) {
                TaintTweakTaintFlowRule(ad.rule.taintTweak, defaultVariableFlowRule)
            } else {
                defaultVariableFlowRule
            }
            val methodAnalyzeMode = if (getConfig().skipAnalyzeNonRelatedMethods) {
                PruneMethodAnalyzeMode.fromTaintAnalyzers(analyzers, ad.depth, ctx)
            } else {
                DefaultMethodAnalyzeMode
            }
            val tsp = TwoStagePointerAnalyze(
                ad.name,
                ad.analyzers.first().entryMethod, AnalyzeContext(PointerFactory()), ad.depth,
                defaultPointerPropagationRule,
                vfr,
                methodAnalyzeMode,
                analyzeTimeInSeconds
            )
            tsp.doPointerAnalyze()
            profiler.entryContext(ad.name, tsp.ctx)
            profiler.startTaintPathCalc(ad.analyzers.first().entryMethod.signature)
            for (analyzer in ad.analyzers) {
                val finder = TaintPathFinder(ctx, tsp.ctx, analyzer.rule, analyzer)
                finder.findPath()
                profiler.stopTaintPathCalc(finder.analyzer.entryMethod.signature)
            }
            val n = finishedTask.addAndGet(1)
            logInfo("${this.javaClass.simpleName} finished $n/${allTask.size}")
        }

        val job = q.runTask()
        for ((_, ads) in allTask) {
            q.addTask(ads)
        }
        q.addTaskFinished()
        job.join()
    }
}

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

import net.bytedance.security.app.engineconfig.EngineConfig
import net.bytedance.security.app.pathfinder.TaintPathFinder
import net.bytedance.security.app.pointer.PointerFactory
import net.bytedance.security.app.taintflow.*
import net.bytedance.security.app.util.TaskQueue
import soot.Scene

/**
whole program pointer analyze,,
 */
class WholeProcessAnalyzeWrapper(
    val ctx: PreAnalyzeContext,
    val analyzers: List<TaintAnalyzer>,
) {
    suspend fun run() {
        val maxDepth = 3000
        val analyzeTimeInSeconds = getConfig().maxPointerAnalyzeTime * 1000.toLong() / 2
        val entry = Scene.v().getMethod(PLUtils.CUSTOM_CLASS_ENTRY)
        val methodAnalyzeMode = if (getConfig().skipAnalyzeNonRelatedMethods) {
            PruneMethodAnalyzeMode.fromTaintAnalyzers(analyzers, maxDepth, ctx)
        } else {
            DefaultMethodAnalyzeMode
        }
        val tsp = TwoStagePointerAnalyze(
            "whole_process_analyze_main",
            entry, AnalyzeContext(PointerFactory()), maxDepth, DefaultPointerPropagationRule(
                EngineConfig.PointerPropagationConfig
            ),
            DefaultVariableFlowRule(EngineConfig.variableFlowConfig),
            methodAnalyzeMode,
            analyzeTimeInSeconds
        )
        tsp.doPointerAnalyze()
        val q = TaskQueue<TaintAnalyzer>(
            "WholeProcessPathFinder",
            getConfig().getMaxPointerAnalyzeThread()
        ) { analyzer, _ ->
            val finder = TaintPathFinder(ctx, tsp.ctx, analyzer.rule, analyzer)
            finder.findPath()
        }
        val job = q.runTask()
        for (analyzer in analyzers) {
            q.addTask(analyzer)
        }
        q.addTaskFinished()
        job.join()
    }
}

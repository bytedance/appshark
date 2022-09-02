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

import net.bytedance.security.app.Log.logInfo
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.rules.IRule
import net.bytedance.security.app.taintflow.TaintAnalyzer
import net.bytedance.security.app.util.profiler

abstract class TaintFlowRuleProcessor(val ctx: PreAnalyzeContext) : IRuleProcessor {
    val analyzers: MutableList<TaintAnalyzer> = ArrayList()

    @Synchronized
    fun collectAnalyzers(analyzers: List<TaintAnalyzer>, rule: IRule) {
        try {
            analyzers.forEach {
                this.analyzers.add(it)
            }
            logInfo("${rule.name} collected ${analyzers.size} analyzers")
        } catch (ex: Exception) {
            ex.printStackTrace()
        }
        profiler.setRuleAnalyzerCount(rule.name, analyzers.size)
    }

}
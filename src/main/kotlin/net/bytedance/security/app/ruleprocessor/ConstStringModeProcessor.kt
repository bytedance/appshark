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

import net.bytedance.security.app.Log
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.rules.ConstStringModeRule
import net.bytedance.security.app.rules.IRule
import net.bytedance.security.app.taintflow.TaintAnalyzer


class ConstStringModeProcessor(ctx: PreAnalyzeContext) : ConstModeProcessor(ctx) {

    override fun name(): String {
        return "ConstStringMode"
    }

    override suspend fun process(rule: IRule) {
        if (rule !is ConstStringModeRule) {
            return //panic?
        }
        val analyzers = ArrayList<TaintAnalyzer>()
        parseConstStringMode(rule, analyzers)
        this.collectAnalyzers(analyzers, rule)
    }

    private suspend fun parseConstStringMode(
        rule: ConstStringModeRule,
        analyzers: MutableList<TaintAnalyzer>
    ) {
        Log.logDebug("\tConstStringMode enabled")
        calcConstValueEntries(rule, rule.sink, analyzers)
    }


}
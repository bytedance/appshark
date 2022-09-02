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

import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.rules.ConstNumberModeRule
import net.bytedance.security.app.rules.IRule
import net.bytedance.security.app.taintflow.TaintAnalyzer

/**
 * The difference from ConstStringMode is that the source is literal number
 */
class ConstNumberModeProcessor(ctx: PreAnalyzeContext) :
    ConstModeProcessor(ctx) {

    override fun name(): String {
        return "ConstNumberMode"
    }

    override suspend fun process(rule: IRule) {
        if (rule !is ConstNumberModeRule) {
            return //panic?
        }
        val analyzers = ArrayList<TaintAnalyzer>()
        parseConstNumberMode(rule, analyzers)
        this.collectAnalyzers(analyzers, rule)
    }

    private suspend fun parseConstNumberMode(rule: ConstNumberModeRule, analyzers: MutableList<TaintAnalyzer>) {
        calcConstValueEntries(rule, rule.sink, analyzers)
    }
}
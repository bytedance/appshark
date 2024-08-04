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


package net.bytedance.security.app.rules

import kotlinx.serialization.json.JsonElement
import net.bytedance.security.app.*


abstract class TaintFlowRule(name: String, ruleData: RuleData) : AbstractRule(name, ruleData) {

    var sink: Map<String, SinkBody>
    val sanitizer: Map<String, LinkedHashMap<String, JsonElement>>?
    var source: SourceBody?

    val polymorphismBackTrace: Boolean

    var primTypeAsTaint: Boolean
    val taintTweak: TaintTweakData?

    val traceDepth: Int

    init {
        sink = ruleData.sink ?: emptyMap()
        sanitizer = ruleData.sanitize
        source = ruleData.source
        polymorphismBackTrace = ruleData.PolymorphismBackTrace == true
        primTypeAsTaint = ruleData.PrimTypeAsTaint == true
        taintTweak = ruleData.TaintTweak
        traceDepth = ruleData.traceDepth!!
    }

    fun isThisRuleNeedLog(): Boolean {
        return getConfig().debugRule == this.name
    }

    fun isThroughEnable(): Boolean {
        return false
    }

    fun isSanitizerV2(): Boolean {
        return this.sanitizer?.isSanitizerV2() ?: false
    }
}

fun Map<String, LinkedHashMap<String, JsonElement>>.isSanitizerV2(): Boolean {
    this.forEach {
        if (it.value.keys.contains("checks")) {
            return true
        }
    }
    return false
}
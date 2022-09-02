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


@file:Suppress("unused")

package net.bytedance.security.app.engineconfig

import kotlinx.serialization.Serializable
import net.bytedance.security.app.TaintTweakData

@Serializable
data class IOData(val I: List<String>, val O: List<String>)
data class Propagation(val from: String, val to: String)


class PointerPropagationConfig {

    //key method, value=>{pointer from  Pair.first propagate to Pair.second}
    var methodSigRule: Map<String, List<Propagation>> = mapOf()
    var methodNameRule: Map<String, List<Propagation>> = mapOf()

    constructor(flowRuleData: FlowRuleData) {
        if (flowRuleData.MethodName != null) {
            this.methodNameRule = VariableFlowConfig.parseMapRule(flowRuleData.MethodName)
        }
        if (flowRuleData.MethodSignature != null) {
            this.methodSigRule = VariableFlowConfig.parseMapRule(flowRuleData.MethodSignature)
        }
    }

    constructor(defaultConfig: PointerPropagationConfig, wrapperData: TaintTweakData) {
        if (wrapperData.MethodName != null) {
            this.methodNameRule = VariableFlowConfig.parseMapRule(wrapperData.MethodName)
        }
        if (wrapperData.MethodSignature != null) {
            this.methodSigRule = VariableFlowConfig.parseMapRule(wrapperData.MethodSignature)
        }
        if (wrapperData.DisableEngineWrapper == true) {
            return
        }
        val methodNameRule = HashMap(defaultConfig.methodNameRule)
        val methodSigRule = HashMap(defaultConfig.methodSigRule)
        this.methodNameRule.forEach { (k, v) ->
            methodNameRule[k] = v
        }
        this.methodSigRule.forEach { (k, v) ->
            methodSigRule[k] = v
        }
        this.methodNameRule = methodNameRule
        this.methodSigRule = methodSigRule
    }


}
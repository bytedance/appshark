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

import net.bytedance.security.app.TaintTweakData


class VariableFlowConfig {
    // taint flow forInstant
    var instantDefaultRule: List<Propagation> = listOf()

    // taint flow for callsite where caller and callee are in the same class
    var instantSelfDefaultRule: List<Propagation> = listOf()

    // taint flow for static method
    var staticDefaultRule: List<Propagation> = listOf()
    var methodSigRule: Map<String, List<Propagation>> = mapOf()
    var methodNameRule: Map<String, List<Propagation>> = mapOf()

    constructor(wrapperData: VariableFlowRuleData) {
        if (wrapperData.InstantDefault != null) {
            this.instantDefaultRule = parseListRule(wrapperData.InstantDefault)
        }
        if (wrapperData.InstantSelfDefault != null) {
            this.instantSelfDefaultRule = parseListRule(wrapperData.InstantSelfDefault)
        }
        if (wrapperData.StaticDefault != null) {
            this.staticDefaultRule = parseListRule(wrapperData.StaticDefault)
        }
        if (wrapperData.MethodName != null) {
            this.methodNameRule = parseMapRule(wrapperData.MethodName)
        }
        if (wrapperData.MethodSignature != null) {
            this.methodSigRule = parseMapRule(wrapperData.MethodSignature)
        }
    }

    constructor(defaultCfg: VariableFlowConfig, wrapperData: TaintTweakData) {
        this.instantDefaultRule = defaultCfg.instantDefaultRule
        this.instantSelfDefaultRule = defaultCfg.instantSelfDefaultRule
        this.staticDefaultRule = defaultCfg.staticDefaultRule
        if (wrapperData.MethodName != null) {
            this.methodNameRule = parseMapRule(wrapperData.MethodName)
        }
        if (wrapperData.MethodSignature != null) {
            this.methodSigRule = parseMapRule(wrapperData.MethodSignature)
        }

        if (wrapperData.DisableEngineWrapper == true) {
            return
        }
        val methodNameRule = HashMap(defaultCfg.methodNameRule)
        val methodSigRule = HashMap(defaultCfg.methodSigRule)
        this.methodNameRule.forEach { (k, v) ->
            methodNameRule[k] = v
        }
        this.methodSigRule.forEach { (k, v) ->
            methodSigRule[k] = v
        }
        this.methodNameRule = methodNameRule
        this.methodSigRule = methodSigRule
    }

    companion object {
        fun parseListRule(jsonObject: Map<String, IOData>): List<Propagation> {
            val r = ArrayList<Propagation>()
            for (ruleObj in jsonObject.values) {
                val inArr = ruleObj.I
                val outArr = ruleObj.O
                for (`in` in inArr) {
                    for (out in outArr) {
                        r.add(Propagation(`in`, out))
                    }
                }
            }
            return r
        }


        fun parseMapRule(jsonObject: Map<String, Map<String, IOData>>): HashMap<String, MutableList<Propagation>> {
            val r = HashMap<String, MutableList<Propagation>>()
            for ((methodName, methodRule) in jsonObject) {
                var ruleList = r[methodName]
                if (ruleList == null) {
                    ruleList = ArrayList()
                    r[methodName] = ruleList
                }
                ruleList.clear()
                for (ruleObj in methodRule.values) {
                    val inArr = ruleObj.I
                    val outArr = ruleObj.O
                    for (`in` in inArr) {
                        for (out in outArr) {
                            ruleList.add(Propagation(`in`, out))
                        }
                    }
                }
            }
            return r
        }
    }

}
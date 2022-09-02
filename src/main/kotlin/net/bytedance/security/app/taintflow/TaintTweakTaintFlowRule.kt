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

import net.bytedance.security.app.TaintTweakData
import net.bytedance.security.app.engineconfig.VariableFlowConfig
import soot.SootMethod

/**
 *  TaintTweak in rule file
 */
class TaintTweakTaintFlowRule(tw: TaintTweakData, private val defaultTaintFlowRule: DefaultVariableFlowRule) :
    IVariableFlowRule {

    var methodRule: Map<String, List<FlowItem>> = HashMap()

    init {

        tw.MethodName?.mapValues {
            VariableFlowConfig.parseListRule(it.value).toFlowItem()
        }?.let {
            this.methodRule += it
        }

        tw.MethodSignature?.mapValues { VariableFlowConfig.parseListRule(it.value).toFlowItem() }?.let {
            this.methodRule += it
        }

    }

    override fun flow(callerMethod: SootMethod, calleeMethod: SootMethod): List<FlowItem> {
        methodRule[calleeMethod.signature]?.let {
            return it
        }
        methodRule[calleeMethod.name]?.let {
            return it
        }
        return defaultTaintFlowRule.flow(callerMethod, calleeMethod)
    }
}
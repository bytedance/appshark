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

import net.bytedance.security.app.engineconfig.Propagation
import net.bytedance.security.app.rules.TaintPosition
import soot.SootMethod

/**
 * taint flow from `from` to `to`
 */
data class FlowItem(val from: TaintPosition, val to: TaintPosition)

fun List<Propagation>.toFlowItem(): List<FlowItem> {
    return this.map { FlowItem(TaintPosition(it.from), TaintPosition(it.to)) }.toList()
}

/**
 * taint flow by user defined rule
 */
interface IVariableFlowRule {
    /**
     * how to process variable flow when callerMethod calls a  calleeMethod
     */
    fun flow(callerMethod: SootMethod, calleeMethod: SootMethod): List<FlowItem>
}

/**
 * pointer propagation by user defined rule
 */
interface IPointerFlowRule {
    /**
     * how to process pointer flow when callerMethod calls a  calleeMethod
     */
    fun flow(calleeMethod: SootMethod): List<FlowItem>?
}


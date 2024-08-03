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


package net.bytedance.security.app.sanitizer.v2

import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.sanitizer.ISanitizer
import net.bytedance.security.app.sanitizer.SanitizeContext
import soot.SootMethod

/**
 * Taint tests are performed on the specified variables,
 * requiring all `taints` are tainted and none of `notTaints` are tainted
 * for example:
"<android.webkit.WebSettings: void setJavaScriptEnabled(boolean)>": {
"TaintCheck":["@this"],
"p0": [1]
}
 * @param constStrings check if any const strings flow to variables ( key of the map).
 *   Integer constants are converted to string
 */
class FieldCheckSanitizerV2(
    val taints: Set<PLLocalPointer>,
    val notTaints: Set<PLLocalPointer>,
    val constStrings: Map<PLLocalPointer, List<String>>,
    val rule: TaintFlowRule,
) : ISanitizer {
    override fun matched(ctx: SanitizeContext): Boolean {
        return true
    }

    fun checkAllPtrIsInOneMethod(): Boolean {
        var method: SootMethod? = null
        val pointers = taints.toMutableList()
        notTaints.forEach { pointers.add(it) }
        constStrings.forEach { pointers.add(it.key) }
        pointers.forEach {
            if (method == null) {
                method = it.method
            } else if (it.method != method) {
                return false
            }
        }
        return true
    }

    companion object {


    }
}
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

import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.sanitizer.ISanitizer
import net.bytedance.security.app.sanitizer.SanitizeContext

/**
 * if these const strings are referenced, they are considered to satisfy the sanitizer condition
 */
class ConstStringCheckSanitizerV2(
    private val positionCheckType: String,
    private val constStrings: List<String>,
    private val rule: TaintFlowRule
) : ISanitizer {
    override fun matched(ctx: SanitizeContext): Boolean {
        //目前只有一种情况，就是taint_to_sink的检查，常量字符串污染到source有需求？
        assert(
            positionCheckType == SANITIZER_POSITION_CHECK_TYPE_SINK
        )
        //or 的关系
        if (positionCheckType == SANITIZER_POSITION_CHECK_TYPE_SINK) {
            for (ptr in ctx.sink) {
                val s = VariableValueCheckSanitizer(ptr, constStrings, rule)
                if (s.matched(ctx)) {
                    return true
                }
            }
        } else {
            throw Exception("ConstStringCheckSanitizerV2 only support sink check")
        }
        return false
    }
}
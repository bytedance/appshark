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


package net.bytedance.security.app.sanitizer

import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.rules.TaintFlowRule
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
class TaintCheckSanitizer(
    val taints: Set<PLLocalPointer>,
    val notTaints: Set<PLLocalPointer>,
    val constStrings: Map<PLLocalPointer, List<String>>,
    val rule: TaintFlowRule,
) : ISanitizer {
    override fun matched(ctx: SanitizeContext): Boolean {
        assert(checkAllPtrIsInOneMethod())
        val allTaints = ctx.ctx.collectPropagation(ctx.src!!, rule.primTypeAsTaint)
        //taints check make sure all this.taints are tainted
        val taintedPass = if (taints.isEmpty()) {
            true
        } else taints.all { allTaints.contains(it) }
        if (!taintedPass) {
            return false
        }
        //notTaints check make sure none of this.notTaints are tainted
        val notTaintedPass = if (notTaints.isEmpty()) {
            true
        } else notTaints.all {
            !allTaints.contains(it)
        }
        if (!notTaintedPass) {
            return false
        }
        var constPass = constStrings.isEmpty()
        found@ for ((dst, patterns) in constStrings) {
            if (constPass) break
            val allPatternTainted = ctx.ctx.collectReversePropagation(dst, rule.primTypeAsTaint)
            for (ptr in allPatternTainted) {
                if (ptr !is PLLocalPointer || !ptr.isConstStr) {
                    continue
                }
                val ptrValue = ptr.variableName
                for (pattern in patterns) {
                    if (isSanitizeStrMatch(pattern, ptrValue)) {
                        constPass = true
                        break@found
                    }
                }
            }
        }
        return constPass
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
        /**
        The sanitizer rule has four forms for constants:
        1. Ordinary integers are converted to string for comparison.
        2. Ordinary strings are compared directly.
        3. for strings contains '*',   a simple regular expression to match
        4. bits match mode
         */
        fun isSanitizeStrMatch(pattern: String, target: String): Boolean {
            val patternSub = pattern.replace("*", "")
            return if (pattern.startsWith("*") && pattern.endsWith("*")) {
                target.contains(patternSub)
            } else if (pattern.startsWith("*")) {
                target.endsWith(patternSub)
            } else if (pattern.endsWith("*")) {
                target.startsWith(patternSub)
            } else {
                if (pattern.endsWith(":&") || pattern.endsWith(":|")) {
                    isBitModeMatch(pattern, target)
                } else {
                    target == patternSub
                }
            }
        }

        /**
         * bits match mode:
         * 67108864:& means the target &67108864 !=0
         * 67108864:| means the target & 67108864==0
         * @param pattern like 67108864:&
         * @param target must be a integer string
         */
        private fun isBitModeMatch(pattern: String, target: String): Boolean {
            try {
                val l = target.toLong()
                val isOr = pattern.endsWith(":|")
                val isAnd = pattern.endsWith(":&")
                val pl = pattern.slice(0 until pattern.length - 2).toLong()
                if (isAnd) {
                    val s = l.and(pl)
                    return s != 0L
                }
                if (isOr) {
                    return l.and(pl) == 0L
                }
                throw Exception("unknown pattern $pattern")
            } catch (ex: NumberFormatException) {
                return false
            }
        }
    }
}
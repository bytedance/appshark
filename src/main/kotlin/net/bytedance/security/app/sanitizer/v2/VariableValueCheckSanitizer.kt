package net.bytedance.security.app.sanitizer.v2

import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.sanitizer.ISanitizer
import net.bytedance.security.app.sanitizer.SanitizeContext
import net.bytedance.security.app.sanitizer.TaintCheckSanitizer

/**
 * 只要由任何一个来自constValues的常量字符串流到了flowTargets中的任何一个变量，就认为满足条件
 * @param flowTarget 是否由任何来自constValues的常量字符串流到了flowTargets
 * @param constValues 常量字符串
 * todo 如果有空了，怎么办呢？
 */
class VariableValueCheckSanitizer(
    val flowTarget: PLLocalPointer,
    val constValues: List<String>,
    val rule: TaintFlowRule
) : ISanitizer {
    override fun matched(ctx: SanitizeContext): Boolean {
        assert(constValues.isNotEmpty())
        val allPatternTainted = ctx.ctx.collectReversePropagation(flowTarget, rule.primTypeAsTaint)
        for (ptr in allPatternTainted) {
            if (ptr !is PLLocalPointer || !ptr.isConstStr) {
                continue
            }
            val ptrValue = ptr.variableName
            for (pattern in constValues) {
                if (TaintCheckSanitizer.isSanitizeStrMatch(pattern, ptrValue)) {
                    return true
                }
            }
        }
        return false
    }
}
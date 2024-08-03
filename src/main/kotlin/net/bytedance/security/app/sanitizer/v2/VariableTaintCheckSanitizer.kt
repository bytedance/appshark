package net.bytedance.security.app.sanitizer.v2

import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.sanitizer.ISanitizer
import net.bytedance.security.app.sanitizer.SanitizeContext

/**
 * 检查taints中的任何一个变量是否
 * 如果positionCheckType是SANITIZER_POSITION_CHECK_TYPE_SOURCE，则检查source出发，是否流到了任何一个taints中的变量
 * 如果positionCheckType是SANITIZER_POSITION_CHECK_TYPE_SINK，则检查sink出发，检查反向传播，是否流到了任何一个taints中的变量
 * @param positionCheckType 只能是SANITIZER_POSITION_CHECK_TYPE_SOURCE或者SANITIZER_POSITION_CHECK_TYPE_SINK
 * @param taints 传播来源
 * @param rule 所在的规则
 * todo sinkPtr是一个Set，明显有问题，预期应该上只有一个才对
 */
class VariableTaintCheckSanitizer(
    val positionCheckType: String,
    val taints: List<PLLocalPointer>,
    val rule: TaintFlowRule
) : ISanitizer {
    override fun matched(ctx: SanitizeContext): Boolean {
        assert(positionCheckType == SANITIZER_POSITION_CHECK_TYPE_SOURCE || positionCheckType == SANITIZER_POSITION_CHECK_TYPE_SINK)
        assert(taints.isNotEmpty())
        if (ctx.sink.size > 1) {
            println("debug")
        }
        val allTaints = when (positionCheckType) {
            SANITIZER_POSITION_CHECK_TYPE_SOURCE -> {
                ctx.ctx.collectPropagation(ctx.src, rule.primTypeAsTaint)
            }
            //todo 这里是集合，应该是有问题的
            SANITIZER_POSITION_CHECK_TYPE_SINK -> {
                val s = mutableSetOf<PLPointer>()
                ctx.sink.forEach {
                    s.addAll(ctx.ctx.collectReversePropagation(it, rule.primTypeAsTaint))
                }
                s
            }

            else -> {
                throw IllegalArgumentException("positionCheckType must be SANITIZER_POSITION_CHECK_TYPE_SOURCE or SANITIZER_POSITION_CHECK_TYPE_SINK")
            }
        }
        //taints check make sure all this.taints are tainted
        val taintedPass = if (taints.isEmpty()) {
            true
        } else taints.any { allTaints.contains(it) }
        return taintedPass
    }
}
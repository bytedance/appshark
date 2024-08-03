package net.bytedance.security.app.sanitizer.v2

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.bytedance.security.app.result.model.toJsonString

//relation字段
const val SANITIZER_RELATION_ALL = "all"
const val SANITIZER_RELATION_ANY = "any"
const val SANITIZER_RELATION_NOT_ANY = "not_any"
const val SANITIZER_RELATION_NOT_ALL = "not_all"

//checkType字段
const val SANITIZER_CHECK_TYPE_METHOD = "method"
const val SANITIZER_CHECK_TYPE_FIELD = "field"
const val SANITIZER_CHECK_TYPE_CONST_STRING = "const_string"

//positionCheckType 字段
const val SANITIZER_POSITION_CHECK_TYPE_CONST_VALUE = "const_value_check"
const val SANITIZER_POSITION_CHECK_TYPE_SOURCE = "taint_from_source"
const val SANITIZER_POSITION_CHECK_TYPE_SINK = "taint_to_sink"

@Serializable
data class SanitizerRule(
    @SerialName("relation") var relation: String = "",
    @SerialName("checks") var checks: ArrayList<SanitizerCheckItem> = arrayListOf()
) {
    //规则中涉及到常量字符串，专门建立索引用
    fun constStrings(): List<String> {
        val result = ArrayList<String>()
        checks.forEach {
            if (it.checkType == SANITIZER_CHECK_TYPE_CONST_STRING) {
                it.subCheckContent.forEach { subCheckContent ->
                    result.addAll(subCheckContent.position)
                }
            }
        }
        return result
    }

    //规则中涉及到的field，专门建立索引用
    fun fields(): List<String> {
        val result = ArrayList<String>()
        checks.forEach {
            if (it.checkType == SANITIZER_CHECK_TYPE_FIELD) {
                result.add(it.fieldSignature!!)
            }
        }
        return result
    }

    //如果有问题，抛出异常
    fun checkRuleValid() {
        try {
            checkInternal()
        } catch (e: Exception) {
            throw IllegalArgumentException("rule=${this.toJsonString()},error=${e.message}")
        }
    }

    private fun checkRelation(relation: String) {
        if (relation != SANITIZER_RELATION_ALL && relation != SANITIZER_RELATION_ANY && relation != SANITIZER_RELATION_NOT_ANY && relation != SANITIZER_RELATION_NOT_ALL) {
            throw IllegalArgumentException("relation field invalid")
        }
    }

    private fun checkInternal() {
        checkRelation(relation)
        checks.forEach {
            checkRelation(it.subCheckContentRelation)
            if (it.checkType != SANITIZER_CHECK_TYPE_METHOD && it.checkType != SANITIZER_CHECK_TYPE_FIELD && it.checkType != SANITIZER_CHECK_TYPE_CONST_STRING) {
                throw IllegalArgumentException("checkType field invalid")
            }
            it.subCheckContent.forEach { subCheckContent ->
                checkRelation(subCheckContent.relation)
                if (subCheckContent.positionCheckType != SANITIZER_POSITION_CHECK_TYPE_CONST_VALUE && subCheckContent.positionCheckType != SANITIZER_POSITION_CHECK_TYPE_SOURCE && subCheckContent.positionCheckType != SANITIZER_POSITION_CHECK_TYPE_SINK) {
                    throw IllegalArgumentException("positionCheckType field invalid")
                }
            }
        }
    }
}

@Serializable
data class SubCheckContent(
    @SerialName("relation") var relation: String = "",
    @SerialName("position") var position: ArrayList<String> = arrayListOf(),
    @SerialName("positionCheckType") var positionCheckType: String = "",
    @SerialName("argumentValue") var argumentValue: List<String>? = null
)

@Serializable
data class SanitizerCheckItem(
    @SerialName("checkType") var checkType: String = "",
    @SerialName("subCheckContentRelation") var subCheckContentRelation: String = "",
    @SerialName("instanceRelation") var instanceRelation: String? = null,
    @SerialName("methodSignature") var methodSignature: String? = null,
    @SerialName("fieldSignature") var fieldSignature: String? = null,
    @SerialName("subCheckContent") var subCheckContent: ArrayList<SubCheckContent> = arrayListOf()
)
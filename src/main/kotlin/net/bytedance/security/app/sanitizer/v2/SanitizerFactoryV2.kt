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

import net.bytedance.security.app.Log
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.result.model.toJsonElement
import net.bytedance.security.app.result.model.toJsonString
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.sanitizer.*
import net.bytedance.security.app.util.Json
import soot.Scene
import soot.jimple.internal.JAssignStmt
import soot.jimple.internal.JInstanceFieldRef
import soot.jimple.internal.JimpleLocal

/**
 * SanitizerFactory is used to create Sanitizer
 * Because a rule can be used in many places, sanitizer is cached for each rule
 */
object SanitizerFactoryV2 : SanitizerFactory() {

    @Synchronized
    override fun createSanitizers(
        rule: TaintFlowRule,
        ctx: PreAnalyzeContext,
    ): List<ISanitizer> {
        if (super.cache.contains(rule.name)) {
            return super.cache[rule.name]!!
        }
        val sanitizes = rule.sanitizer ?: return listOf()
        //如果是v1，先走v1
        if (!rule.isSanitizerV2()) {
            return super.createSanitizers(rule, ctx)
        }

        //v2的话，需要先重新编码解码
        val sanitizersObj = sanitizes.toJsonElement()
        val sanitizersV2: Map<String, SanitizerRule> = Json.decodeFromJsonElement(sanitizersObj)
        val results = mutableListOf<ISanitizer>()
        sanitizersV2.forEach { (_, sanitizer) ->
            sanitizer.checkRuleValid()
            results.add(createRuleForSanitizerRule(sanitizer, ctx, rule))
        }
        Log.logInfo("sanitizersV2=${sanitizersV2.toJsonString()}")
        cache[rule.name] = results
        return results
    }

    private fun createRuleForSanitizerRule(
        sanitizers: SanitizerRule,
        ctx: PreAnalyzeContext,
        rule: TaintFlowRule
    ): ISanitizer {
        val checksRules = createRuleFromChecks(sanitizers.checks, ctx, rule)
        return createRulesWithRelation(sanitizers.relation, checksRules)
    }

    fun createRulesWithRelation(relation: String, rules: List<ISanitizer>): ISanitizer {
        when (relation) {
            SANITIZER_RELATION_ALL -> {
                return SanitizerAndRules(rules)
            }

            SANITIZER_RELATION_ANY -> {
                return SanitizeOrRules(rules)
            }

            SANITIZER_RELATION_NOT_ANY -> {
                return SanitizerNotRule(SanitizeOrRules(rules))
            }

            SANITIZER_RELATION_NOT_ALL -> {
                return SanitizerNotRule(SanitizerAndRules(rules))
            }

            else -> {
                throw IllegalArgumentException("unsupported relation: $relation")
            }
        }
    }

    private fun createRuleFromChecks(
        checks: List<SanitizerCheckItem>,
        ctx: PreAnalyzeContext,
        rule: TaintFlowRule
    ): List<ISanitizer> {
        val results = mutableListOf<ISanitizer>()
        checks.forEach { check ->
            when (check.checkType) {
                SANITIZER_CHECK_TYPE_CONST_STRING -> {
                    results.add(createConstStringSanitizer(check, ctx, rule))
                }

                SANITIZER_CHECK_TYPE_METHOD -> {
                    results.add(createMethodSanitizer(check, check.methodSignature!!, ctx, rule))
                }

                SANITIZER_CHECK_TYPE_FIELD -> {
                    results.add(createFieldSanitizer(check, check.fieldSignature!!, ctx, rule))
                }
            }
        }
        return results
    }

    private fun createConstStringSanitizer(
        check: SanitizerCheckItem,
        ctx: PreAnalyzeContext,
        rule: TaintFlowRule
    ): ISanitizer {
        val sanitizers = ArrayList<ISanitizer>()
        check.subCheckContent.forEach { subCheckContent ->
            val subSanitizers = ArrayList<ISanitizer>()
            subCheckContent.position.forEach { pattern ->
                subSanitizers.add(ConstStringCheckSanitizerV2(subCheckContent.positionCheckType, listOf(pattern), rule))
            }
            sanitizers.add(createRulesWithRelation(subCheckContent.relation, subSanitizers))
        }
        return createRulesWithRelation(check.subCheckContentRelation, sanitizers)
    }

    private fun createFieldSanitizer(
        check: SanitizerCheckItem,
        fieldSig: String,
        ctx: PreAnalyzeContext,
        rule: TaintFlowRule
    ): ISanitizer {
        val field = Scene.v().grabField(fieldSig)
        //找不到field，就认为通不过
        if (field == null || field.isStatic) {
            return MustNotPassSanitizer()
        }
        val resultOrSanitizers = ArrayList<ISanitizer>()
        val callsites = ctx.findFieldCallSite(field)
        //需要针对每一个call site创建一个sanitzer，只要其中任何一个callsite满足条件，就是ok的
        for (callsite in callsites) {
            val stmt = callsite.stmt
            val sanitizersLevel1 = ArrayList<ISanitizer>()
            check.subCheckContent.forEach { subCheckContent ->
                val sanitizerLevel2 = ArrayList<ISanitizer>()
                subCheckContent.position.forEach { position ->
                    val pointers = ArrayList<PLLocalPointer>()
                    assert(position == PLUtils.THIS_FIELD || position == PLUtils.DATA_FIELD)
                    if (position == PLUtils.THIS_FIELD) {
                        val fieldRef = stmt.fieldRef as JInstanceFieldRef
                        val ptr =
                            PLLocalPointer(callsite.method, (fieldRef.base as JimpleLocal).name, fieldRef.base.type)
                        pointers.add(ptr)
                    } else if (position == PLUtils.DATA_FIELD) {
                        val ret = (stmt as? JAssignStmt)?.leftOp as? JimpleLocal ?: null
                        if (ret != null) {
                            val ptr = PLLocalPointer(callsite.method, ret.name, ret.type)
                            pointers.add(ptr)
                        }
                    } else {
                        throw IllegalArgumentException("unsupported position: $position")
                    }
                    if (pointers.isEmpty()) {
                        sanitizerLevel2.add(MustNotPassSanitizer())
                    } else {
                        sanitizerLevel2.add(
                            VariableTaintCheckSanitizer(
                                subCheckContent.positionCheckType,
                                pointers,
                                rule
                            )
                        )
                    }
                }
                sanitizersLevel1.add(createRulesWithRelation(subCheckContent.relation, sanitizerLevel2))
            }
            resultOrSanitizers.add(createRulesWithRelation(check.subCheckContentRelation, sanitizersLevel1))
        }

        //create or rules for field
        var relation = SANITIZER_RELATION_ANY
        if (check.instanceRelation != null && check.instanceRelation!!.isNotEmpty()) {
            relation = check.instanceRelation!!
        }
        return createRulesWithRelation(relation, resultOrSanitizers)
    }

    private fun createMethodSanitizer(
        check: SanitizerCheckItem,
        methodSignature: String,
        ctx: PreAnalyzeContext,
        rule: TaintFlowRule
    ): ISanitizer {
        return TaintCheckSanitizerParserV2(check, methodSignature, ctx, rule).createMethodSanitizer()
    }
}
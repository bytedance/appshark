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

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import net.bytedance.security.app.Log.logInfo
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.SinkBody
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.util.Json
import net.bytedance.security.app.util.isFieldSignature
import soot.RefType
import soot.Scene
import soot.jimple.internal.JAssignStmt
import soot.jimple.internal.JInstanceFieldRef
import soot.jimple.internal.JimpleLocal

/**
 * SanitizerFactory is used to create Sanitizer
 * Because a rule can be used in many places, sanitizer is cached for each rule
 */
object SanitizerFactory {
    private val cache = HashMap<String, List<ISanitizer>>()

    @Synchronized
    fun createSanitizers(
        rule: TaintFlowRule,
        ctx: PreAnalyzeContext,
    ): List<ISanitizer> {
        if (cache.contains(rule.name)) {
            return cache[rule.name]!!
        }
        val sanitizes = rule.sanitize ?: return listOf()
        val result = ArrayList<ISanitizer>()
        for ((_, sanitizeRules) in sanitizes) {
            val andRules = ArrayList<ISanitizer>()
            for ((key, body) in sanitizeRules) {
                if (key == "ConstString") {
                    andRules.add(createConstStringSanitizer(body, ctx))
                } else if (key.isFieldSignature()) {
                    andRules.add(createFieldSanitizer(body, key, ctx, rule))
                } else {
                    val sinkBody: SinkBody = Json.decodeFromJsonElement(body)
                    val p = TaintCheckSanitizerParser(ctx, sinkBody, key, rule)
                    andRules.add(p.createMethodSanitizer())
                }
            }
            if (andRules.size == 1) {
                result.add(andRules.first())
            } else if (andRules.size > 1) {
                result.add(SanitizerAndRules(andRules))
            } else {
                logInfo("no sanitizer for rule: ${rule.name}")
            }

        }
        cache[rule.name] = result
        return result
    }

    @Synchronized
    fun clearCache() {
        cache.clear()
    }

    private fun createConstStringSanitizer(array: JsonElement, ctx: PreAnalyzeContext): ISanitizer {
        val constStrings: List<String> = Json.decodeFromJsonElement(array)
        val pointers = ArrayList<PLLocalPointer>()
        for (pattern in constStrings) {
            val constCallMap = ctx.findConstStringPatternCallSite(pattern)
            for (callsite in constCallMap) {
                for (str in callsite.constString()) {
                    val ptr = PLLocalPointer(
                        callsite.method,
                        PLUtils.constStrSig(str),
                        RefType.v("java.lang.String")
                    )
                    pointers.add(ptr)
                }
            }
        }
        return ConstStringCheckSanitizer(pointers)
    }


    /**
     * create a sanitizer for a object field
     *   TaintCheck:
     *   - @this check this object of the field is tainted
     *   - @data check this field is tainted
    "<android.content.pm.ActivityInfo: boolean exported>": {
    "TaintCheck":["@this"]
    }
     */
    private fun createFieldSanitizer(
        ruleObj: JsonElement,
        fieldSig: String,
        ctx: PreAnalyzeContext,
        rule: TaintFlowRule
    ): ISanitizer {
        val field = Scene.v().grabField(fieldSig)
        if (field == null || ruleObj.jsonObject.isEmpty() || field.isStatic) {
            return MustNotPassSanitizer()
        }
        val sinkBody: SinkBody = Json.decodeFromJsonElement(ruleObj)
        assert(sinkBody.TaintCheck != null)
        var checkBase = false
        var checkField = false
        for (obj in sinkBody.TaintCheck!!) {
            if (obj == PLUtils.THIS_FIELD) {
                checkBase = true
            } else if (obj == PLUtils.DATA_FIELD) {
                checkField = true
            }
        }
        if (!checkBase && !checkField) {
            return MustNotPassSanitizer()
        }
        val callsites = ctx.findFieldCallSite(field)
        val pointers = ArrayList<PLLocalPointer>()
        for (callsite in callsites) {
            val stmt = callsite.stmt
            if (checkBase) {
                val fieldRef = stmt.fieldRef as JInstanceFieldRef
                val ptr = PLLocalPointer(callsite.method, (fieldRef.base as JimpleLocal).name, fieldRef.base.type)
                pointers.add(ptr)
            }
            if (checkField) {
                val ret = (stmt as? JAssignStmt)?.leftOp as? JimpleLocal ?: continue
                val ptr = PLLocalPointer(callsite.method, ret.name, ret.type)
                pointers.add(ptr)
            }
        }
        return TaintCheckSanitizer(pointers.toSet(), emptySet(), emptyMap(), rule)
    }

}
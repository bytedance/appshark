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


package net.bytedance.security.app.rules

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.bytedance.security.app.*
import net.bytedance.security.app.util.Json
import net.bytedance.security.app.util.isFieldSignature

open class DirectModeRule(name: String, ruleData: RuleData) : TaintFlowRule(name, ruleData), IRuleConstStringPattern,
    IRuleNewInstance,
    IRuleField {
    override val mode: String = "DirectMode"
    val entry: Entry?
    val sinkRules: List<RuleObjBody>?
    val sourceRules: List<RuleObjBody>?
    val throughAPI: ThroughAPI?


    private var isInitComplete = false
    suspend fun initIfNeeded() {
        if (!isInitComplete) {
            val ss = processSourceAndSink()
            this.source = ss.first
            this.sink = ss.second
        }
        isInitComplete = true
    }

    override fun constStringPatterns(): Set<String> {
        val constStrings = source?.ConstString?.let {
            ArrayList(it)
        } ?: ArrayList()
        if (sanitize != null) {
            val values = sanitize.values
            for (m in values) {
                for ((sig, sinkBodyElement) in m) {
                    if (sig == "ConstString") {
                        val strings: List<String> = Json.decodeFromJsonElement(sinkBodyElement)
                        constStrings.addAll(strings)
                        continue
                    }
                    val sinkBody = Json.decodeFromJsonElement<SinkBody>(sinkBodyElement)
                    if (sinkBody.pstar != null) {
                        val pstar = sinkBody.pstar
                        for (p in pstar) {
                            if (p.jsonPrimitive.isString) {
                                val s = p.jsonPrimitive.content
                                if (!s.startsWith("@")) {
                                    constStrings.add(s)
                                }
                            }
                        }
                    }
                    if (sinkBody.pmap != null) {
                        for ((_, value) in sinkBody.pmap!!) {
                            for (p in value) {
                                if (p.jsonPrimitive.isString) {
                                    val s = p.jsonPrimitive.content
                                    if (!s.startsWith("@")) {
                                        constStrings.add(s)
                                    }
                                }
                            }
                        }
                    }

                }
            }
        }
        return constStrings.toSet()
    }

    override fun newInstances(): Set<String> {
        source?.NewInstance?.let {
            return it.toSet()
        }
        return emptySet()
    }

    override fun fields(): Set<String> {
        val fieldPatternResults = source?.StaticField?.toMutableSet() ?: HashSet()
        source?.Field?.let {
            for (field in it) {
                fieldPatternResults.add(field)
            }
        }
        if (sanitize != null) {
            val values = sanitize.values
            for (m in values) {
                for ((key, _) in m) {
                    if (key.isFieldSignature()) {
                        fieldPatternResults.add(key)
                    }
                }
            }
        }
        val results = HashSet<String>()
        fieldPatternResults.forEach { fieldPattern ->
            MethodFinder.checkAndParseFieldSignature(fieldPattern).forEach { field ->
                results.add(field.signature)
            }
        }
        return results
    }


    private suspend fun processSourceAndSink(): Pair<SourceBody, Map<String, SinkBody>> {
        val source = this.source ?: SourceBody()
        var sink = this.sink
        this.sourceRules?.forEach {
            parseSourceRuleObj(it, source)
        }
        this.sinkRules?.forEach {
            sink = parseSinkRuleObj(it, sink)
        }
        return Pair(source, sink)
    }

    private suspend fun parseSourceRuleObj(ruleObj: RuleObjBody, source: SourceBody) {
        source.Return = source.Return ?: JsonArray(emptyList())
        val secRules = loadRuleFromFile(ruleObj.ruleFile!!)
        secRules.keys.forEach { ruleName ->
            if (ruleObj.include.isNotEmpty() && !ruleObj.include.contains(ruleName)) {
                return@forEach
            }
            val jsonObj = secRules[ruleName]!!
            val ruleData: RuleData = Json.decodeFromJsonElement(jsonObj)
            if (ruleObj.fromAPIMode) {
                if (ruleData.APIMode == true) {
                    ruleData.sink?.run {
                        val filter1: (String) -> Boolean = { x -> x.contains("(") }
                        source.RuleObjReturn = listMerge(source.RuleObjReturn, this.keys.toList(), filter1)
                        val filter2: (String) -> Boolean = { x -> !x.contains("(") }
                        source.StaticField = listMerge(source.StaticField, this.keys.toList(), filter2)
                    }
                }
            } else {
                ruleData.source?.run {
                    source.RuleObjReturn = listMerge(
                        source.RuleObjReturn,
                        if (Return is JsonArray) {
                            Json.decodeFromJsonElement<List<String>>(
                                Return as JsonArray
                            ).toMutableList()
                        } else source.RuleObjReturn
                    )
                    source.UseJSInterface = if (source.UseJSInterface) source.UseJSInterface else UseJSInterface
                    source.Param = mapMerge(source.Param, Param)
                    source.StaticField = listMerge(source.StaticField, StaticField)
                    source.ConstString = listMerge(source.ConstString, ConstString)
                    source.NewInstance = listMerge(source.NewInstance, NewInstance)
                }

            }
        }

    }

    private suspend fun loadRuleFromFile(ruleFile: String): JsonObject {
        val curRulePath = "${getConfig().rulePath}/$ruleFile"
        val jsonStr = Rules.loadConfigOrQuit(curRulePath)
        return Json.parseToJsonElement(jsonStr).jsonObject
    }

    private suspend fun parseSinkRuleObj(ruleObj: RuleObjBody, sink: Map<String, SinkBody>?): Map<String, SinkBody> {
        var sink2 = sink?.toMap() ?: mapOf()
        val secRules = loadRuleFromFile(ruleObj.ruleFile!!)
        secRules.keys.forEach { ruleName ->
            if (ruleObj.include.isNotEmpty() && !ruleObj.include.contains(ruleName)) {
                return@forEach
            }
            val jsonObj = secRules[ruleName]!!
            val ruleData: RuleData = Json.decodeFromJsonElement(jsonObj)
            sink2 = mapMerge(sink2, ruleData.sink)
        }
        return sink2
    }

    private fun listMerge(
        old: List<String>,
        other: List<String>,
        filter: (String) -> Boolean = { true }
    ): List<String> {
        val new = ArrayList<String>()
        for (s in old) {
            new.add(s)
        }
        for (s in other) {
            if (!new.contains(s) && filter(s)) {
                new.add(s)
            }
        }
        return new
    }

    private fun <K, V> mapMerge(
        old: Map<K, V>,
        other: Map<K, V>?,
        reduce: (V, V) -> V = { _, b -> b }
    ): Map<K, V> {
        val new = HashMap<K, V>()
        for ((k, v) in old) {
            new[k] = v
        }
        other?.forEach { (key, value) ->
            new[key] = new[key]?.let { reduce(value, it) } ?: value
        }
        return new
    }

    init {
        entry = ruleData.entry
        sinkRules = ruleData.sinkRuleObj
        sourceRules = ruleData.sourceRuleObj
        throughAPI = ruleData.throughAPI
    }


}
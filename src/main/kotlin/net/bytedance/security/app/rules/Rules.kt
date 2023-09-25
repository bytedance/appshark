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

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.jsonObject
import net.bytedance.security.app.Log
import net.bytedance.security.app.RuleData
import net.bytedance.security.app.util.Json
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths

class Rules(val rulePaths: List<String>, val factory: IRuleFactory) : IRulesForContext {
    val allRules: MutableList<IRule> = ArrayList()

    suspend fun loadRules() {
        rulePaths.forEach {
            val jsonStr = loadConfigOrQuit(it)
            val rules = Json.parseToJsonElement(jsonStr)
            for ((ruleName, ruleBody) in rules.jsonObject) {
                val ruleData: RuleData = Json.decodeFromJsonElement(ruleBody)
                if (ruleData.sanitizer != null) {   // Compatible with old and new rules
                    ruleData.sanitize = ruleData.sanitizer
                    ruleData.sanitizer = null
                }
                val rule = factory.create(ruleName, ruleData)
                allRules.add(rule)
            }
        }
    }

    override fun constStringPatterns(): Set<String> {
        val s = HashSet<String>()
        allRules.forEach {
            if (it is IRuleConstStringPattern)
                s.addAll(it.constStringPatterns())
        }
        return s
    }

    override fun newInstances(): Set<String> {
        val s = HashSet<String>()
        allRules.forEach {
            if (it is IRuleNewInstance)
                s.addAll(it.newInstances())
        }
        return s
    }

    override fun fields(): Set<String> {
        val s = HashSet<String>()
        allRules.forEach {
            if (it is IRuleField) {
                s.addAll(it.fields())
            }
        }
        return s
    }

    companion object {
        suspend fun loadConfigOrQuit(path: String): String {
            Log.logInfo("Load config file $path")
            val jsonStr =
                withContext(Dispatchers.IO) {
                    try {
                        String(Files.readAllBytes(Paths.get(path)))
                    } catch (e: IOException) {
                        Log.logErr("read config file $path failed")
                        throw Exception("read config file $path failed")
                    }
                }

            return jsonStr
        }
    }
}
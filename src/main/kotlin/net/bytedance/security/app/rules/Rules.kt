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
    val UNLIMITED = -1

    suspend fun loadRules(targetSdk: Int = UNLIMITED, minSdk: Int = UNLIMITED) {
        rulePaths.forEach {
            val jsonStr = loadConfigOrQuit(it)
            val rules = Json.parseToJsonElement(jsonStr)
            for ((ruleName, ruleBody) in rules.jsonObject) {
                val ruleData: RuleData = Json.decodeFromJsonElement(ruleBody)
                if (ruleData.sanitizer != null) {   // Compatible with old and new rules
                    ruleData.sanitize = ruleData.sanitizer
                    ruleData.sanitizer = null
                }
                if ((targetSdk == UNLIMITED || targetSdk in parseSdkVersion(ruleData.targetSdk)) &&
                    (minSdk == UNLIMITED || parseSdkVersion("$minSdk:").any { it in parseSdkVersion(ruleData.runtimeSdk) })) {
                    val rule = factory.create(ruleName, ruleData)
                    allRules.add(rule)
                } else {
                    Log.logDebug("ignore rule: $ruleName")
                }
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

        fun parseSdkVersion(input: String): List<Int> {
            val MIN_SDK_VERSION = 9     // Android 2.3
            val MAX_SDK_VERSION = 50    // for future

            if (input.isBlank() || input.trim() == ":") {
                return (MIN_SDK_VERSION..MAX_SDK_VERSION).toList()
            }
            return input.split(Regex("[,\\s]+")).flatMap { part ->
                when {
                    part.contains(":") -> {
                        val splitPart = part.split(":")
                        val hasStart = splitPart[0].isNotEmpty()
                        val hasEnd = splitPart[1].isNotEmpty()
                        when {
                            !hasStart && !hasEnd -> listOf()
                            !hasEnd -> {
                                (splitPart[0].toIntOrNull() ?: return@flatMap listOf())..MAX_SDK_VERSION
                            }
                            !hasStart -> {
                                (MIN_SDK_VERSION..(splitPart[1].toIntOrNull() ?: return@flatMap listOf())).toList()
                            }
                            else -> {
                                val start = splitPart[0].toIntOrNull() ?: return@flatMap listOf()
                                val end = splitPart[1].toIntOrNull() ?: return@flatMap listOf()
                                (start..end).toList()
                            }
                        }
                    }
                    else -> listOf(part.toIntOrNull() ?: return@flatMap listOf())
                }
            }
        }
    }
}

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

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.getConfig
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.io.File

internal class RulesTest {

    fun createDefaultRules(): Rules {
        val rules = Rules(
            listOf(
                "${getConfig().rulePath}/unZipSlip.json",
            ),
            RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        return rules
    }

    @Test
    fun constStringPatterns() {
        val rules = createDefaultRules()
        println(rules.constStringPatterns().toSortedSet().toList())
    }

    @Test
    fun newInstances() {
        val rules = createDefaultRules()
        println(rules.newInstances().toSortedSet().toList())
    }

    @Test
    fun fields() {
        val rules = createDefaultRules()
        println(rules.fields().toSortedSet().toList())
    }


    @Test
    fun testAllRules() {
        val rules = Rules(
            getAllRules(),
            RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        println("const strings=${rules.constStringPatterns().toSortedSet().toList()}")
        println("fields=${rules.fields().toSortedSet().toList()}")
        println("new instances=${rules.newInstances().toSortedSet().toList()}")
    }

    @Test
    fun testParseSdkVersion() {
        assertEquals(
            (9..50).toList(),
            Rules.parseSdkVersion("")
        )
        assertEquals(
            (9..50).toList(),
            Rules.parseSdkVersion(":")
        )
        assertEquals(
            (9..10).toList() + listOf(15) + (25..30).toList() + (45..50).toList(),
            Rules.parseSdkVersion(":10, 15, 25:30, 45:")
        )
    }

    companion object {
        fun getAllRules(): List<String> {
            val rules = ArrayList<String>()
            File(getConfig().rulePath).walk().forEach {
//            println(it.absolutePath)
                if (it.absolutePath.endsWith(".json") || it.absolutePath.endsWith(".json5")) {
                    rules.add(it.absolutePath)
                }
            }
            println(rules)
            return rules
        }

        fun createDefaultRules(): Rules {
            val rules = Rules(
                getAllRules(),
                RuleFactory()
            )
            runBlocking {
                rules.loadRules()
            }
            return rules
        }
    }
}
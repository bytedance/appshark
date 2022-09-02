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


package net.bytedance.security.app.ruleprocessor

import kotlinx.coroutines.*
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.rules.IRulesForContext
import net.bytedance.security.app.rules.RulesTest
import net.bytedance.security.app.taintflow.TaintAnalyzer
import org.junit.jupiter.api.Test
import test.SootHelper
import test.TestHelper

internal open class RuleProcessorFactoryTest {

    init {
        SootHelper.initSoot(
            "RuleProcessorFactoryTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata")
        )
    }


    @Test
    fun testCreateAllRules() {
        runBlocking { createAllRules() }
    }

    suspend fun createAllRules() {
        val rules = RulesTest.createDefaultRules()
        val ctx = createContext(rules)
        val jobs = ArrayList<Job>()
        val scope = CoroutineScope(Dispatchers.Default)
        val analyzers = ArrayList<TaintAnalyzer>()
        for (r in rules.allRules) {
            val rp = RuleProcessorFactory.create(ctx, r.mode)
            val job = scope.launch {
                println("process ${rp.javaClass.name} ${r.name}")
                rp.process(r)
                if (rp is TaintFlowRuleProcessor) {
                    synchronized(analyzers) {
                        analyzers.addAll(rp.analyzers)
                    }
                }
            }
            jobs.add(job)
        }

        jobs.joinAll()
        println("analyzers: ${analyzers.size}")
    }

    companion object {
        suspend fun createContext(rules: IRulesForContext): PreAnalyzeContext {
            val ctx = PreAnalyzeContext()
            ctx.createContext(rules, true)
            return ctx
        }
    }
}
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

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.MethodFinder
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.rules.RuleFactory
import net.bytedance.security.app.rules.Rules
import net.bytedance.security.app.taintflow.TaintAnalyzer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import test.SootHelper
import test.TestHelper

internal class SliceModeProcessorTest {
    init {
        SootHelper.initSoot(
            "SliceModeProcessorTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata")
        )
    }

    @BeforeEach
    fun clearCache() {
        MethodFinder.clearCache()
    }

    @Test
    fun createAnalyzersForSourceAndSink() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/unZipSlipSliceMode.json"
            ), RuleFactory()
        )

        runBlocking {
            rules.loadRules()
            val ctx = RuleProcessorFactoryTest.createContext(rules)
            PLUtils.dumpClass("net.bytedance.security.app.ruleprocessor.testdata.ZipSlip")
            val rp = RuleProcessorFactory.create(ctx, rules.allRules[0].mode)
            rp.process(rules.allRules[0])
            val analyzers = (rp as SliceModeProcessor).analyzers
            assertEquals(3, analyzers.size)
            analyzers.forEach {
                assertEquals(1, it.data.sourcePointerSet.size)
                assertEquals(1, it.data.sinkPointerSet.size)
            }

            mustContains(
                analyzers,
                "<net.bytedance.security.app.ruleprocessor.testdata.ZipSlip: void UnZipFolderFix1(java.lang.String,java.lang.String)>->\$r3",
                "UnZipFolderFix1"
            )
            mustContains(
                analyzers,
                "<net.bytedance.security.app.ruleprocessor.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>->\$r3",
                "UnZipFolder"
            )
            mustContains(
                analyzers,
                "<net.bytedance.security.app.ruleprocessor.testdata.ZipSlip: void UnZipFolderFix2(java.lang.String,java.lang.String)>->\$r4",
                "UnZipFolderFix2"
            )
        }
    }

    companion object {
        fun mustContains(analyzers: List<TaintAnalyzer>, sourcePtrStr: String, entry: String) {
            for (analyzer in analyzers) {
                if (analyzer.entryMethod.name == entry) {
                    try {
                        val srcPtr = analyzer.data.pointerIndexMap[sourcePtrStr]!!
                        if (analyzer.data.sourcePointerSet.contains(srcPtr)) {
                            return
                        }
                    } catch (ex: Exception) {
                        ex.printStackTrace()
                    }
                }

            }
            throw Exception("not found $entry")
        }
    }
}
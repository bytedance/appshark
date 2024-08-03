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

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.MethodFinder
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.ruleprocessor.RuleProcessorFactoryTest
import net.bytedance.security.app.rules.DirectModeRule
import net.bytedance.security.app.rules.RuleFactory
import net.bytedance.security.app.rules.Rules
import net.bytedance.security.app.rules.SliceModeRule
import net.bytedance.security.app.sanitizer.*
import net.bytedance.security.app.taintflow.TwoStagePointerAnalyzeTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import soot.RefType
import soot.Scene
import soot.SootMethod
import test.SootHelper
import test.TestHelper

internal class SanitizerFactoryV2Test {
    init {
        SootHelper.initSoot(
            "SanitizerFactoryTestV2",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata")
        )
    }

    @BeforeEach
    fun clearCache() {
        SanitizerFactoryV2.clearCache()
        MethodFinder.clearCache()
    }

    @Test
    fun testLoadRule() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/testrule.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as SliceModeRule
        assert(taintedRule.sanitizer!!.size > 0)
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            assertTrue(sanitizers.size > 0)
        }
    }

    fun getUnzipFolderSrc(): PLLocalPointer {
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.v2.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>")
        return PLLocalPointer(m, "\$r3", RefType.v("java.lang.String"))
    }

    fun getUnZipFolderFix1Src(): PLLocalPointer {
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.v2.testdata.ZipSlip: void UnZipFolderFix1(java.lang.String,java.lang.String)>")
        return PLLocalPointer(m, "\$r3", RefType.v("java.lang.String"))
    }

    fun sanitizersZipslipResult(sanitizers: List<ISanitizer>, src: PLLocalPointer): Boolean {
        val entry = Scene.v().getMethod("<net.bytedance.security.app.sanitizer.v2.testdata.ZipSlip: void f()>")
        return sanitizersResult(sanitizers, src, entry)
    }

    fun sanitizersResult(
        sanitizers: List<ISanitizer>,
        src: PLLocalPointer,
        entry: SootMethod,
        sink: PLLocalPointer? = null
    ): Boolean {
        val tsp = TwoStagePointerAnalyzeTest.createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }
        for (s in sanitizers) {
            val sinks = mutableSetOf<PLLocalPointer>()
            if (sink != null) {
                sinks.add(sink!!)
            }
            if (s.matched(SanitizeContext(tsp.ctx, src, sinks))) {
                return true
            }
        }
        return false
    }

    @Test
    fun createFieldSanitizers() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/unZipSlipFieldSanitizer.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.v2.testdata.ZipSlip")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            assertTrue(sanitizers.size == 1)
            var sanitizerL1 = sanitizers[0]
            assertTrue(sanitizerL1 is SanitizerAndRules)
            //有多少个调用点，就会有多少orRules,v2以后sanitizers的嵌套关系深太多了
            val sanitizerOrRules = (sanitizerL1 as SanitizerAndRules).rules[0]
            val sanitizerL2 = (sanitizerOrRules as SanitizeOrRules).rules[0]
            assertTrue(sanitizerL2 is SanitizerAndRules)
            val sanitizerL3 = (sanitizerL2 as SanitizerAndRules).rules[0]
            assertTrue(sanitizerL3 is SanitizerAndRules)
            val sanitizerL4 = (sanitizerL3 as SanitizerAndRules).rules[0]
//            assertTrue((s0 as ConstStringCheckSanitizer).consts.size == 1)
            val taints = (sanitizerL4 as VariableTaintCheckSanitizer).taints
            assertTrue(sanitizerL4.positionCheckType == SANITIZER_POSITION_CHECK_TYPE_SOURCE)
            assertTrue(taints.size == 1)
            assertTrue(taints.first().method.name == "UnZipFolder")
            println("sanitizers=${taints}")
            assertFalse(sanitizersZipslipResult(sanitizers, getUnZipFolderFix1Src()))
        }
    }

    @Test
    fun createMethod1() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/unZipSlipMethodCheck1.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.DumpClass("net.bytedance.security.app.sanitizer.testdata.ZipSlip")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
            var sanitizerL1 = sanitizers[0]
            assertTrue(sanitizerL1 is SanitizerAndRules)
            //有多少个调用点，就会有多少orRules,v2以后sanitizers的嵌套关系深太多了
            val sanitizerOrRules = (sanitizerL1 as SanitizerAndRules).rules[0]
            val sanitizerL2 = (sanitizerOrRules as SanitizeOrRules).rules[0]
            assertTrue(sanitizerL2 is SanitizerAndRules)
            //check L2:taint_from_source
            if (true) {
                val sanitizerL3 = (sanitizerL2 as SanitizerAndRules).rules[0]
                assertTrue(sanitizerL3 is SanitizerAndRules)
                val sanitizerL4 = (sanitizerL3 as SanitizerAndRules).rules[0]
                val tcs = sanitizerL4 as VariableTaintCheckSanitizer
                assertEquals(tcs.taints.size, 1)
                assertEquals(tcs.taints.first().method.name, "UnZipFolderFix1")
                assertEquals(tcs.positionCheckType, SANITIZER_POSITION_CHECK_TYPE_SOURCE)

                assertFalse(sanitizersZipslipResult(sanitizers, getUnzipFolderSrc()))
                assertTrue(sanitizersZipslipResult(sanitizers, getUnZipFolderFix1Src()))
            }
            //check L2:const_value_check
            if (true) {
                val sanitizerL3 = (sanitizerL2 as SanitizerAndRules).rules[1]
                assertTrue(sanitizerL3 is SanitizerAndRules)
                val sanitizerL4 = (sanitizerL3 as SanitizerAndRules).rules[0]
                //实参是常量字符串，当时就出结果了
                assertTrue(sanitizerL4 is MustPassSanitizer)
            }
        }
    }

    @Test
    fun createMethod2() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/unZipSlipMethodCheck2.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.DumpClass("net.bytedance.security.app.sanitizer.testdata.ZipSlip")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
            var sanitizerL1 = sanitizers[0]
            assertTrue(sanitizerL1 is SanitizerAndRules)
            //有多少个调用点，就会有多少orRules,v2以后sanitizers的嵌套关系深太多了
            val sanitizerOrRules = (sanitizerL1 as SanitizerAndRules).rules[0]
            val sanitizerL2 = (sanitizerOrRules as SanitizeOrRules).rules[0]
            assertTrue(sanitizerL2 is SanitizerAndRules)
            val sanitizerL3 = (sanitizerL2 as SanitizerAndRules).rules[0]
            assertTrue(sanitizerL3 is SanitizerAndRules)
            val sanitizerL4 = (sanitizerL3 as SanitizerAndRules).rules[0]
            //实参是常量字符串，当时就出结果了
            assertTrue(sanitizerL4 is VariableValueCheckSanitizer)
            assertFalse(sanitizersZipslipResult(sanitizers, getUnzipFolderSrc()))
            assertFalse(sanitizersZipslipResult(sanitizers, getUnZipFolderFix1Src()))
        }
    }

    @Test
    fun createMethod4() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/unZipSlipMethodCheck4.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.DumpClass("net.bytedance.security.app.sanitizer.testdata.ZipSlip")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
            assertTrue(sanitizersZipslipResult(sanitizers, getUnzipFolderSrc()))
            assertTrue(sanitizersZipslipResult(sanitizers, getUnZipFolderFix1Src()))
        }
    }

    @Test
    fun testPendingIntentMutableService() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/pendingIntentMutableService.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
        }
    }

    fun createPendingIntentMutableVar(varName: String, functionName: String): PLLocalPointer {
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.v2.testdata.PendingIntentMutable: void $functionName()>")
        return PLLocalPointer(m, varName, RefType.v("java.lang.String"))
    }

    fun sanitizersPendingIntentResult(
        sanitizers: List<ISanitizer>,
        src: PLLocalPointer,
        functionName: String
    ): Boolean {
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.v2.testdata.PendingIntentMutable: void $functionName()>")
        return sanitizersResult(sanitizers, src, entry)
    }

    @Test
    fun testPendingIntentMutableProvider() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/pendingIntentMutableProvider.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val entryFunction = "f3"
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)

            assertFalse(
                sanitizersPendingIntentResult(
                    sanitizers,
                    createPendingIntentMutableVar("\$r0", entryFunction),
                    entryFunction
                )
            )
            assertTrue(
                sanitizersPendingIntentResult(
                    sanitizers,
                    createPendingIntentMutableVar("\$r1", entryFunction),
                    entryFunction
                )
            )
        }
    }

    @Test
    fun testPendingIntentMutableBroadcast() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/pendingIntentMutableBroadcast.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val entryFunction = "f4"
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)

            assertTrue(
                sanitizersPendingIntentResult(
                    sanitizers,
                    createPendingIntentMutableVar("\$r0", entryFunction),
                    entryFunction
                )
            )
        }
    }

    @Test
    fun testPendingIntentMutableActivity() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/pendingIntentMutableActivity.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val entryFunction = "f1"
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
        }
    }

    fun sanitizersSdcardResult(
        sanitizers: List<ISanitizer>,
        sink: PLLocalPointer
    ): Boolean {
        val entry = Scene.v().getMethod("<net.bytedance.security.app.sanitizer.v2.testdata.TestSdCardVisit: void f()>")
        //在这个场景下主要关心sink，所有src是什么无所谓
        val src = PLLocalPointer(entry, "\$r0", RefType.v("java.lang.String"))
        return sanitizersResult(sanitizers, src, entry, sink)
    }

    fun getTestProblem1Sink(): PLLocalPointer {
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.v2.testdata.TestSdCardVisit: void TestProblem1()>")
        return PLLocalPointer(m, "\$r4", RefType.v("java.lang.String"))
    }


    fun getTestNoProblem1Sink(): PLLocalPointer {
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.v2.testdata.TestSdCardVisit: void TestNoProblem1()>")
        return PLLocalPointer(m, "\$r4", RefType.v("java.lang.String"))
    }

    fun getTestNoProblem2Sink(): PLLocalPointer {
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.v2.testdata.TestSdCardVisit: void TestNoProblem2()>")
        return PLLocalPointer(m, "\$r1", RefType.v("java.lang.String"))
    }

    //新增的taint_to_sink的检测规则
    @Test
    fun testSdcardProblem1Rule1() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/visitsdcard.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.v2.testdata.TestSdCardVisit")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)

            assertFalse(sanitizersSdcardResult(sanitizers, getTestProblem1Sink()))
        }
    }

    @Test
    fun testSdcardNoProblem1Rule1() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/visitsdcard.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.v2.testdata.TestSdCardVisit")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            assertTrue(sanitizersSdcardResult(sanitizers, getTestNoProblem1Sink()))
        }
    }

    @Test
    fun testSdcardProblem1Rule2() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/visitsdcard2.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.v2.testdata.TestSdCardVisit")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            assertFalse(sanitizersSdcardResult(sanitizers, getTestProblem1Sink()))
        }
    }

    @Test
    fun testSdcardNoProblem1Rule2() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/visitsdcard2.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.v2.testdata.TestSdCardVisit")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            /*
            虽然没有从source到sink到路径，但是确实有从getExternalFilesDir到sink到路径，所以不能sanitizer掉
             */
            assertFalse(sanitizersSdcardResult(sanitizers, getTestNoProblem1Sink()))
        }
    }

    @Test
    fun testSdcardNoProblem2Rule2() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/visitsdcard2.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        runBlocking {
            val ctx = RuleProcessorFactoryTest.createContext(rules)
            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.v2.testdata.TestSdCardVisit")
            val sanitizers = SanitizerFactoryV2.createSanitizers(taintedRule, ctx)
            /*
            有从so到sink到路径
            但是没有访问
             */
            assertTrue(sanitizersSdcardResult(sanitizers, getTestNoProblem2Sink()))
        }
    }
}
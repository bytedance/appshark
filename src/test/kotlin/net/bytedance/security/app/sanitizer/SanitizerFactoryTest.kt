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

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonPrimitive
import net.bytedance.security.app.MethodFinder
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.ruleprocessor.RuleProcessorFactoryTest.Companion.createContext
import net.bytedance.security.app.rules.DirectModeRule
import net.bytedance.security.app.rules.RuleFactory
import net.bytedance.security.app.rules.Rules
import net.bytedance.security.app.taintflow.TwoStagePointerAnalyzeTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import soot.RefType
import soot.Scene
import soot.SootMethod
import soot.jimple.LongConstant
import soot.jimple.NullConstant
import soot.jimple.StringConstant
import test.SootHelper
import test.TestHelper

internal class SanitizerFactoryTest {
    init {
        SootHelper.initSoot(
            "SanitizerFactoryTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata")
        )
    }

    @BeforeEach
    fun clearCache() {
        SanitizerFactory.clearCache()
        MethodFinder.clearCache()
    }

    @Test
    fun createConstStringSanitizers() {
        val rules = Rules(
            listOf(
                "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata/unZipSlipConstStringSanitizer.json"
            ), RuleFactory()
        )
        runBlocking {
            rules.loadRules()
        }
        val taintedRule = rules.allRules[0] as DirectModeRule
        val strs = taintedRule.constStringPatterns()
        assert(strs.size == 1)
        runBlocking {
            val ctx = createContext(rules)
            val sanitizers = SanitizerFactory.createSanitizers(taintedRule, ctx)
            assertTrue(sanitizers.size == 1)
            val s0 = sanitizers[0]
            assertTrue(s0 is ConstStringCheckSanitizer)
            println("sanitizers=${(s0 as ConstStringCheckSanitizer).constStrings}")
            assertTrue(sanitizersZipslipResult(sanitizers, getUnzipFolderSrc()))
        }
    }

    fun getUnzipFolderSrc(): PLLocalPointer {
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>")
        return PLLocalPointer(m, "\$r3", RefType.v("java.lang.String"))
    }

    fun getUnZipFolderFix1Src(): PLLocalPointer {
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.testdata.ZipSlip: void UnZipFolderFix1(java.lang.String,java.lang.String)>")
        return PLLocalPointer(m, "\$r3", RefType.v("java.lang.String"))
    }

    fun sanitizersZipslipResult(sanitizers: List<ISanitizer>, src: PLLocalPointer): Boolean {
        val entry = Scene.v().getMethod("<net.bytedance.security.app.sanitizer.testdata.ZipSlip: void f()>")
        return sanitizersResult(sanitizers, src, entry)
    }

    fun sanitizersPendingIntentResult(
        sanitizers: List<ISanitizer>,
        src: PLLocalPointer,
        functionName: String
    ): Boolean {
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable: void $functionName()>")
        return sanitizersResult(sanitizers, src, entry)
    }

    fun sanitizersResult(sanitizers: List<ISanitizer>, src: PLLocalPointer, entry: SootMethod): Boolean {
        val tsp = TwoStagePointerAnalyzeTest.createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }
        for (s in sanitizers) {
            if (s.matched(SanitizeContext(tsp.ctx, src))) {
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
        val strs = taintedRule.fields()
        assert(strs.size == 1)
        runBlocking {
            val ctx = createContext(rules)
//            PLUtils.DumpClass("net.bytedance.security.app.sanitizer.testdata.ZipSlip")
            val sanitizers = SanitizerFactory.createSanitizers(taintedRule, ctx)
            assertTrue(sanitizers.size == 1)
            val s0 = sanitizers[0]
            assertTrue(s0 is TaintCheckSanitizer)
//            assertTrue((s0 as ConstStringCheckSanitizer).consts.size == 1)
            val taints = (s0 as TaintCheckSanitizer).taints
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
            val ctx = createContext(rules)
//            PLUtils.DumpClass("net.bytedance.security.app.sanitizer.testdata.ZipSlip")
            val sanitizers = SanitizerFactory.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
            val s0 = sanitizers[0]
            assertTrue(s0 is SanitizeOrRules)
            val so = s0 as SanitizeOrRules
//            assertTrue((s0 as ConstStringCheckSanitizer).consts.size == 1)
            assertEquals(so.rules.size, 1)
            val tcs = so.rules[0] as TaintCheckSanitizer
            assertEquals(tcs.taints.size, 1)
            assertEquals(tcs.taints.first().method.name, "UnZipFolderFix1")
            assertTrue(tcs.notTaints.isEmpty())
            assertTrue(tcs.constStrings.isEmpty())

            assertFalse(sanitizersZipslipResult(sanitizers, getUnzipFolderSrc()))
            assertTrue(sanitizersZipslipResult(sanitizers, getUnZipFolderFix1Src()))
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
            val ctx = createContext(rules)
//            PLUtils.DumpClass("net.bytedance.security.app.sanitizer.testdata.ZipSlip")
            val sanitizers = SanitizerFactory.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
            val s0 = sanitizers[0]
            assertTrue(s0 is MethodCheckSanitizer)
            val mc = s0 as MethodCheckSanitizer
            assertEquals(mc.methods.size, 1)
            assertTrue(sanitizersZipslipResult(sanitizers, getUnzipFolderSrc()))
            assertTrue(sanitizersZipslipResult(sanitizers, getUnZipFolderFix1Src()))
        }
    }

    @Test
    fun testConstant() {
        val str = StringConstant.v("aaa")
        assertEquals("aaa", str.getStringValue())
        val n = LongConstant.v(3)
        assertEquals("3", n.getStringValue())
        val nullStr = NullConstant.v()
        assertEquals(nullStr.getStringValue(), "null")
    }

    @Test
    fun jsonConstant() {
        val n = Json.parseToJsonElement("1")
        assertEquals(n.jsonPrimitive.content, "1")
        val str = Json.parseToJsonElement("\"aaa\"")
        assertEquals(str.jsonPrimitive.content, "aaa")
        val nullStr = Json.parseToJsonElement("null")
        assertEquals(nullStr.jsonPrimitive.content, "null")
    }

    data class Table(val pattern: String, val target: String, val result: Boolean)

    @Test
    fun isSanitizeStrMatch() {
        val samples = listOf(
            Table("12", "12", true),
            Table("12*", "12", true),
            Table("*12", "12", true),
            Table("67108864:&", "67108865", true),
            Table("67108864:&", "123456", false),
            Table("67108864:|", "67108865", false),
            Table("67108864:|", "123456", true),
        )
        for (s in samples) {
            val r = TaintCheckSanitizer.isSanitizeStrMatch(s.pattern, s.target)
            assertEquals(s.result, r, s.pattern + "," + s.target)
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
            val ctx = createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable")
            val sanitizers = SanitizerFactory.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
            val s0 = sanitizers[0]
            assertTrue(s0 is SanitizeOrRules)
            val so = s0 as SanitizeOrRules
//            assertTrue((s0 as ConstStringCheckSanitizer).consts.size == 1)
            assertEquals(so.rules.size, 0)

        }
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
            val ctx = createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable")
            val sanitizers = SanitizerFactory.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
            val s0 = sanitizers[0]
            assertTrue(s0 is SanitizeOrRules)
            val so = s0 as SanitizeOrRules
//            assertTrue((s0 as ConstStringCheckSanitizer).consts.size == 1)
            assertEquals(so.rules.size, 1)
            val tcs = so.rules[0] as TaintCheckSanitizer
            assertEquals(tcs.taints.size, 1)
            assertEquals(tcs.taints.first().method.name, entryFunction)
            assertTrue(tcs.notTaints.isEmpty())
            assertTrue(tcs.taints.isNotEmpty())
            assertTrue(tcs.constStrings.isEmpty())

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

    fun createPendingIntentMutableVar(varName: String, functionName: String): PLLocalPointer {
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable: void $functionName()>")
        return PLLocalPointer(m, varName, RefType.v("java.lang.String"))
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
            val ctx = createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable")
            val sanitizers = SanitizerFactory.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
            val s0 = sanitizers[0]
            assertTrue(s0 is SanitizeOrRules)
            val so = s0 as SanitizeOrRules
//            assertTrue((s0 as ConstStringCheckSanitizer).consts.size == 1)
            assertEquals(so.rules.size, 1)
            val tcs = so.rules[0] as TaintCheckSanitizer
            assertEquals(tcs.taints.size, 1)
            assertEquals(tcs.taints.first().method.name, entryFunction)
            assertTrue(tcs.notTaints.isEmpty())
            assertTrue(tcs.taints.isNotEmpty())
            assertTrue(tcs.constStrings.isEmpty())


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
            val ctx = createContext(rules)
//            PLUtils.dumpClass("net.bytedance.security.app.sanitizer.testdata.PendingIntentMutable")
            val sanitizers = SanitizerFactory.createSanitizers(taintedRule, ctx)
            assertEquals(sanitizers.size, 1)
            val s0 = sanitizers[0]
            assertTrue(s0 is SanitizeOrRules)
            val so = s0 as SanitizeOrRules
//            assertTrue((s0 as ConstStringCheckSanitizer).consts.size == 1)
            assertEquals(so.rules.size, 0)
        }
    }
}
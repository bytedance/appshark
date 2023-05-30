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


package net.bytedance.security.app.taintflow

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.preprocess.AnalyzePreProcessor
import net.bytedance.security.app.preprocess.MethodFieldConstCacheVisitor
import net.bytedance.security.app.preprocess.MethodSSAVisitor
import net.bytedance.security.app.preprocess.MethodStmtFieldCache
import net.bytedance.security.app.taintflow.TwoStagePointerAnalyzeTest.Companion.createDefaultTwoStagePointerAnalyze
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import soot.Scene
import soot.UnknownType
import test.SootHelper
import test.TestHelper

internal class ContextInsensitiveTest {
    init {
        val ctx = PreAnalyzeContext()
        val cam = AnalyzePreProcessor(10, ctx)

        SootHelper.initSoot(
            "ConextInsensitiveTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata")
        )
        cam.addMethodVisitor {
            MethodSSAVisitor()
        }.addMethodVisitor {
            MethodFieldConstCacheVisitor(
                ctx,
                MethodStmtFieldCache(),
                HashSet(), HashSet(), HashSet()
            )
        }
        runBlocking { cam.run() }
    }


    @Test
    fun testNormalFlow() {
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.taintflow.testdata.InsensitiveTest: void NormalFlow()>")
        val tsp = createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }
        PLUtils.dumpClass("net.bytedance.security.app.taintflow.testdata.InsensitiveTest")
        val srcName = "\$r1"
        val sinkName = "\$r2"
        val srcPtr = tsp.pt.allocLocal(entry, srcName, UnknownType.v())
        val sinkPtr = tsp.pt.allocLocal(entry, sinkName, UnknownType.v())
        val allTaint = tsp.ctx.collectPropagation(srcPtr, false)
        assertTrue(allTaint.contains(sinkPtr))
    }

    @Test
    fun testInvalidFlow() {
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.taintflow.testdata.InsensitiveTest: void HasInvalidFlow()>")
        val tsp = createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }
        PLUtils.dumpClass("net.bytedance.security.app.taintflow.testdata.InsensitiveTest")
        val srcName = "\$r1"
        val sinkName = "\$r3"
        val srcPtr = tsp.pt.allocLocal(entry, srcName, UnknownType.v())
        val sinkPtr = tsp.pt.allocLocal(entry, sinkName, UnknownType.v())
        val allTaint = tsp.ctx.collectPropagation(srcPtr, false)
        assertTrue(allTaint.contains(sinkPtr))
    }

}
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


package net.bytedance.security.app.preprocess

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.DEBUG
import net.bytedance.security.app.Log
import net.bytedance.security.app.PreAnalyzeContext
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import soot.Scene
import test.SootHelper
import test.TestHelper

internal class CallGraphTest {
    private val ctx = PreAnalyzeContext()
    private val cam = AnalyzePreProcessor(10, ctx)

    init {
        Log.setLevel(DEBUG)
        SootHelper.initSoot(
            "CallGraphTest",
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
    fun testSimple() {
        val src = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object methodImplementedInSub()>")
        val sink = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.TestCallgraph: void sink()>")
        val ss = CallGraph.SourceAndSinkCross(false, src, sink, 10, false, ctx.callGraph)
        val result = ss.traceAndCross()
        assertTrue(result != null)
        assertEquals(
            "<net.bytedance.security.app.preprocess.testdata.TestCallgraph: void calldirect(net.bytedance.security.app.preprocess.testdata.Sub)>",
            result!!.entryMethod.signature
        )
        assertEquals(6, result.depth)
    }

    @Test
    fun testLessDepth() {
        val src = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object methodImplementedInSub()>")
        val sink = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.TestCallgraph: void sink()>")
        val ss = CallGraph.SourceAndSinkCross(false, src, sink, 3, false, ctx.callGraph)
        val result = ss.traceAndCross()
        assertTrue(result == null)
    }

    @Test
    fun testHeirNotFound() {
        val src = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object methodImplementedInSub()>")
        val sink = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.TestCallgraph: void sink()>")
        val ss = CallGraph.SourceAndSinkCross(false, src, sink, 10, false, ctx.callGraph)
        val result = ss.traceAndCross()
        assertTrue(result == null)
    }

    @Test
    fun testHeir() {
        val src = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object methodImplementedInSub2()>")
        val sink = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.TestCallgraph: void sink()>")
        val ss = CallGraph.SourceAndSinkCross(true, src, sink, 10, false, ctx.callGraph)
        val result = ss.traceAndCross()
        assertTrue(result != null)
        assertEquals(
            "<net.bytedance.security.app.preprocess.testdata.TestCallgraph: void callHeir(net.bytedance.security.app.preprocess.testdata.Base)>",
            result!!.entryMethod.signature
        )
        assertEquals(6, result.depth)
    }

    @Test
    fun testHeir2() {
        val src = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Sub2: java.lang.Object methodImplementedInSub2()>")
        val sink = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.TestCallgraph: void sink()>")
        val ss = CallGraph.SourceAndSinkCross(true, src, sink, 10, false, ctx.callGraph)
        val result = ss.traceAndCross()
        assertTrue(result != null)
        assertEquals(
            "<net.bytedance.security.app.preprocess.testdata.TestCallgraph: void callHeir(net.bytedance.security.app.preprocess.testdata.Base)>",
            result!!.entryMethod.signature
        )
        assertEquals(6, result.depth)
    }

}
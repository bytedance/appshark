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
import net.bytedance.security.app.engineconfig.EngineConfig
import net.bytedance.security.app.pathfinder.TaintPathFinder
import net.bytedance.security.app.pointer.PointerFactory
import net.bytedance.security.app.preprocess.AnalyzePreProcessor
import net.bytedance.security.app.preprocess.MethodFieldConstCacheVisitor
import net.bytedance.security.app.preprocess.MethodSSAVisitor
import net.bytedance.security.app.preprocess.MethodStmtFieldCache
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import soot.Scene
import soot.SootMethod
import soot.UnknownType
import test.SootHelper
import test.TestHelper

internal class TwoStagePointerAnalyzeTest {
    init {
        val ctx = PreAnalyzeContext()
        val cam = AnalyzePreProcessor(10, ctx)

        SootHelper.initSoot(
            "TwiStagePointerAnalyzeTest",
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
    fun solver() {
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.taintflow.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>")
        val tsp = createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }
        PLUtils.dumpClass("net.bytedance.security.app.taintflow.testdata.ZipSlip")
        val srcName = "\$r3"
        val sinkName = "\$r21"
        val srcPtr = tsp.pt.allocLocal(entry, srcName, UnknownType.v())
        val sinkPtr = tsp.pt.allocLocal(entry, sinkName, UnknownType.v())
        val allTaint = tsp.ctx.collectPropagation(srcPtr, false)
        assertTrue(allTaint.contains(sinkPtr))
        println(tsp.ctx.dump())
        val path =
            TaintPathFinder.bfsSearch(srcPtr, setOf(sinkPtr), tsp.ctx.variableFlowGraph, 256, "test")
                ?.map {
                    it.signature()
                }
        println("path=$path")
    }

    @Test
    fun solverStaticMethod() {
        PLUtils.dumpClass("net.bytedance.security.app.taintflow.testdata.TaintExample")
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.taintflow.testdata.TaintExample: void TaintCrossStaticMethod()>")
        val pt = PointerFactory()
        val tsp = createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }

        val srcPtr = pt.allocLocal(
            Scene.v()
                .getMethod("<net.bytedance.security.app.taintflow.testdata.TaintExample: java.lang.Object staticSource1()>"),
            "\$r0",
            UnknownType.v()
        )
        val sinkPtr = pt.allocLocal(entry, "\$r0", UnknownType.v())
        val allTaint = tsp.ctx.collectPropagation(srcPtr, false)
        assertTrue(allTaint.contains(sinkPtr))
        println(tsp.ctx.dump())
    }

    @Test
    fun solverInstanceMethod() {
        PLUtils.dumpClass("net.bytedance.security.app.taintflow.testdata.TaintExample")
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.taintflow.testdata.TaintExample: void TaintCrossInstanceMethod()>")
        val pt = PointerFactory()
        val tsp = createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }

        val srcPtr = pt.allocLocal(
            Scene.v()
                .getMethod("<net.bytedance.security.app.taintflow.testdata.TaintExample: java.lang.Object instanceSource1()>"),
            "\$r0",
            UnknownType.v()
        )
        val falseSinkPtr = pt.allocLocal(entry, "\$r0", UnknownType.v())
        val allTaint = tsp.ctx.collectPropagation(srcPtr, false)
        assertTrue(!allTaint.contains(falseSinkPtr))
        val sinkPtr = pt.allocLocal(entry, "\$r1", UnknownType.v())
        assertTrue(tsp.ctx.collectPropagation(srcPtr, false).contains(sinkPtr))
    }

    @Test
    fun flowCrossMethodFalsePositiveExample() {
        PLUtils.dumpClass("net.bytedance.security.app.taintflow.testdata.TaintExample")
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.taintflow.testdata.TaintExample: void flowCrossMethod()>")
        val sinkMethod =
            Scene.v().getMethod("<net.bytedance.security.app.taintflow.testdata.Taint: void sink(java.lang.Object)>")
        val notSinkMethod =
            Scene.v().getMethod("<net.bytedance.security.app.taintflow.testdata.Taint: void notSink(java.lang.Object)>")

        val pt = PointerFactory()
        val tsp = createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }

        val srcPtr = pt.allocLocal(entry, "\$r0", UnknownType.v())
        val falseSrcPtr = pt.allocLocal(entry, "\$r3", UnknownType.v())
        val sinkPtr = pt.allocLocal(sinkMethod, "@parameter0", UnknownType.v())
        val falseSinkPtr = pt.allocLocal(notSinkMethod, "@parameter0", UnknownType.v())


        val srcTainted = tsp.ctx.collectPropagation(srcPtr, false)
        val falseSrcTainted = tsp.ctx.collectPropagation(falseSrcPtr, false)

        assertTrue(srcTainted.contains(falseSinkPtr))
        assertTrue(srcTainted.contains(sinkPtr))
        assertTrue(falseSrcTainted.contains(falseSinkPtr))
        assertTrue(falseSrcTainted.contains(sinkPtr))
    }

    companion object {

        fun createDefaultTwoStagePointerAnalyze(entry: SootMethod): TwoStagePointerAnalyze {
            val tsp = TwoStagePointerAnalyze(
                entry.signature,
                entry,
                AnalyzeContext(PointerFactory()),
                3,
                DefaultPointerPropagationRule(EngineConfig.PointerPropagationConfig),
                DefaultVariableFlowRule(EngineConfig.variableFlowConfig),
                DefaultMethodAnalyzeMode,
                100000
            )
            return tsp
        }

    }

}
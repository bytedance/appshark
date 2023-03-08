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


package net.bytedance.security.app.pathfinder

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.pointer.*
import net.bytedance.security.app.preprocess.AnalyzePreProcessor
import net.bytedance.security.app.preprocess.MethodFieldConstCacheVisitor
import net.bytedance.security.app.preprocess.MethodSSAVisitor
import net.bytedance.security.app.preprocess.MethodStmtFieldCache
import net.bytedance.security.app.taintflow.TwoStagePointerAnalyze
import net.bytedance.security.app.taintflow.TwoStagePointerAnalyzeTest.Companion.createDefaultTwoStagePointerAnalyze
import net.bytedance.security.app.ui.TaintPathModeHtmlWriter
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import soot.Scene
import soot.SootMethod
import soot.UnknownType
import soot.jimple.Stmt
import test.SootHelper
import test.TestHelper
import java.util.*

internal class TaintFlowEdgeFinderTest {
    init {
        val ctx = PreAnalyzeContext()
        val cam = AnalyzePreProcessor(10, ctx)

        SootHelper.initSoot(
            "TaintFlowEdgeFinderTest",
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

    fun getZipSlipContext(): TwoStagePointerAnalyze {
        try {
            val entry = Scene.v()
                .getMethod("<net.bytedance.security.app.pathfinder.testdata.ZipSlip: void f()>")
            val tsp = createDefaultTwoStagePointerAnalyze(entry)
            runBlocking {
                tsp.doPointerAnalyze()
            }
            return tsp
        } catch (ex: Exception) {
            val path = System.getProperty("user.dir")
            throw Exception("Failed to load ZipSlip, please check the path: $path, ex=$ex")
        }

    }

    class Path(val src: PLPointer, val dst: PLPointer, val edges: List<TaintEdge>?) {
        fun isValid(): Boolean {
            if (edges != null && edges.isNotEmpty()) {
                return true
            }
            if (src is PLPtrObjectField && src.field == PLUtils.DATA_FIELD) {
                return true
            }
            if (dst is PLPtrObjectField && dst.field == PLUtils.DATA_FIELD) {
                return true
            }
            return false
        }

        override fun toString(): String {
            return "$src->$dst: edges=${edges} "
        }
    }

    fun assertPathValid(path: List<PLPointer>) {
        val edges = ArrayList<Path>()
        for (i in 0 until path.size - 1) {
            val edge = TaintFlowEdgeFinder.getPossibleEdge(path[i], path[i + 1])
            edges.add(Path(path[i], path[i + 1], edge))
        }
        edges.forEach {
            Assertions.assertTrue(it.isValid(), "path=${it}")
        }

        val edgesWithRange = TaintPathModeHtmlWriter.getTaintEdges(path)
        println("path len=${path.size}")
        edgesWithRange.forEach {
            println("${it.first.method.name}======> ${it.second}")
//            assertTrue(it.isValid(), "path=${it}")
        }
        val methods = ArrayList<SootMethod>()
        val stmts = ArrayList<List<Stmt>>()
        val edgesInMethod = ArrayList<List<PLPointer>>()
        TaintPathModeHtmlWriter.mergeTaintPath(methods, stmts, edgesInMethod, path)
        methods.forEachIndexed { index, sootMethod ->
            println("index=$index, method=${sootMethod.name}")
            stmts[index].forEach {
                println("$it")
            }
            Assertions.assertEquals(stmts[index].size, HashSet(stmts[index]).size)
            edgesInMethod[index].forEach {
                println("$it")
            }
            Assertions.assertEquals(edgesInMethod[index].size, HashSet(edgesInMethod[index]).size)
        }
    }

    @Test
    fun testZipSlip() {
        //this case depends on the version of the Java compiler, only JDK 11.0.12 tests passed and JDK 1.8 tests failed
        PLUtils.dumpClass("net.bytedance.security.app.pathfinder.testdata.ZipSlip")
        val tsp = getZipSlipContext()
        val unzipFolder = Scene.v()
            .getMethod("<net.bytedance.security.app.pathfinder.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>")
        val srcName = "\$r3"
        val sinkName = "\$r21"
        val srcPtr = tsp.pt.allocLocal(unzipFolder, srcName, UnknownType.v())
        val sinkPtr = tsp.pt.allocLocal(unzipFolder, sinkName, UnknownType.v())

        val path =
            TaintPathFinder.bfsSearch(srcPtr, setOf(sinkPtr), tsp.ctx.variableFlowGraph, 256, "test")
        println("path=$path")
        Assertions.assertTrue(path != null)
        Assertions.assertEquals(3, path!!.size)
        Assertions.assertEquals(srcPtr.signature(), path.first().signature())
        Assertions.assertEquals(sinkPtr.signature(), path.last().signature())
        assertPathValid(path)
    }

    @Test
    fun testMergeTaintPath() {
        //this case depends on the version of the Java compiler, only JDK 11.0.12 tests passed and JDK 1.8 tests failed
        PLUtils.dumpClass("net.bytedance.security.app.pathfinder.testdata.ZipSlip")
        val tsp = getZipSlipContext()
        val m1 = Scene.v().getMethod("<net.bytedance.security.app.pathfinder.testdata.ZipSlip: void f()>")
        val m2 = Scene.v().getMethod("<net.bytedance.security.app.pathfinder.testdata.ZipSlip: void <init>()>")
        val m3 = Scene.v()
            .getMethod("<net.bytedance.security.app.pathfinder.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>")
        val m4 = Scene.v()
            .getMethod("<net.bytedance.security.app.pathfinder.testdata.ZipSlip: void UnZipFolderFix1(java.lang.String,java.lang.String)>")
        val src = tsp.ctx.pt.allocLocal(m3, "\$r3", UnknownType.v())
        val node0 = tsp.ctx.pt.allocLocal(m3, "\$r10", UnknownType.v())
        val node1 = tsp.ctx.pt.allocLocal(m3, "\$r13", UnknownType.v())
        // test path has @data
        val obj = tsp.ctx.pt.allocObject(UnknownType.v(), m4, null, 11);
        val field = tsp.ctx.pt.allocObjectField(obj, PLUtils.DATA_FIELD, UnknownType.v())
        val sink = tsp.ctx.pt.allocLocal(m2, "\$r0", UnknownType.v())
        val path = listOf<PLPointer>(src, node0, node1, field, sink)
        println("path=$path")
        testpath(path)
    }

    fun testpath(path: List<PLPointer>) {
        val edges = ArrayList<Path>()
        for (i in 0 until path.size - 1) {
            val edge = TaintFlowEdgeFinder.getPossibleEdge(path[i], path[i + 1])
            edges.add(Path(path[i], path[i + 1], edge))
        }

        val edgesWithRange = TaintPathModeHtmlWriter.getTaintEdges(path)
        println("path len=${path.size}")
        edgesWithRange.forEach {
            println("${it.first.method.name}======> ${it.second}")
//            assertTrue(it.isValid(), "path=${it}")
        }
        val methods = ArrayList<SootMethod>()
        val stmts = ArrayList<List<Stmt>>()
        val edgesInMethod = ArrayList<List<PLPointer>>()
        TaintPathModeHtmlWriter.mergeTaintPath(methods, stmts, edgesInMethod, path)
        methods.forEachIndexed { index, sootMethod ->
            println("index=$index, method=${sootMethod.name}")
            stmts[index].forEach {
                println("$it")
            }
            Assertions.assertEquals(stmts[index].size, HashSet(stmts[index]).size)
            edgesInMethod[index].forEach {
                println("$it")
            }
            Assertions.assertEquals(edgesInMethod[index].size, HashSet(edgesInMethod[index]).size)
        }
    }

    @Test
    fun testZipSlipFromConstString() {
        PLUtils.dumpClass("net.bytedance.security.app.pathfinder.testdata.ZipSlip")
        val tsp = getZipSlipContext()
        val unzipFolder = Scene.v()
            .getMethod("<net.bytedance.security.app.pathfinder.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>")

        val sinkName = "\$r21"

        val srcPtr = tsp.pt.allocLocal(tsp.entryMethod, PLUtils.constStrSig("path1"), UnknownType.v())
        val sinkPtr = tsp.pt.allocLocal(unzipFolder, sinkName, UnknownType.v())


        val path =
            TaintPathFinder.bfsSearch(srcPtr, setOf(sinkPtr), tsp.ctx.variableFlowGraph, 256, "test")
        println("path=$path")
        Assertions.assertTrue(path != null)
        Assertions.assertEquals(9, path!!.size)
        Assertions.assertEquals(srcPtr.signature(), path.first().signature())
        Assertions.assertEquals(sinkPtr.signature(), path.last().signature())
        assertPathValid(path)
    }

    @Test
    fun pathInstanceMethod() {
        PLUtils.dumpClass("net.bytedance.security.app.pathfinder.testdata.TaintExample")
        PLUtils.dumpClass("net.bytedance.security.app.pathfinder.testdata.Taint")
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.pathfinder.testdata.TaintExample: void TaintCrossInstanceMethod()>")
        val pt = PointerFactory()
        val tsp = createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }

        val srcPtr = pt.allocLocal(
            Scene.v()
                .getMethod("<net.bytedance.security.app.pathfinder.testdata.TaintExample: java.lang.Object instanceSource1()>"),
            "\$r0",
            UnknownType.v()
        )
        val falseSinkPtr = pt.allocLocal(entry, "\$r0", UnknownType.v())
        val allTaint = tsp.ctx.collectPropagation(srcPtr, false)
        Assertions.assertTrue(!allTaint.contains(falseSinkPtr))
        val sinkPtr = pt.allocLocal(entry, "\$r1", UnknownType.v())
        Assertions.assertTrue(tsp.ctx.collectPropagation(srcPtr).contains(sinkPtr))
        val path =
            TaintPathFinder.bfsSearch(srcPtr, setOf(sinkPtr), tsp.ctx.variableFlowGraph, 256, "test")
        Assertions.assertTrue(path != null)
        Assertions.assertEquals(3, path!!.size)
        Assertions.assertEquals(srcPtr.signature(), path.first().signature())
        Assertions.assertEquals(sinkPtr.signature(), path.last().signature())
        assertPathValid(path)
    }

    @Test
    fun testInstanceDispatchNotUseCHA() {
        PLUtils.dumpClass("net.bytedance.security.app.pathfinder.testdata.CHATest\$ClassFlow")
        PLUtils.dumpClass("net.bytedance.security.app.pathfinder.testdata.CHATest\$Base")
        PLUtils.dumpClass("net.bytedance.security.app.pathfinder.testdata.CHATest\$Sub")
        val entry = Scene.v()
            .getMethod("<net.bytedance.security.app.pathfinder.testdata.CHATest\$ClassFlow: void flow()>")
        val pt = PointerFactory()
        val tsp = createDefaultTwoStagePointerAnalyze(entry)
        runBlocking {
            tsp.doPointerAnalyze()
        }

        val srcPtr = pt.allocLocal(
            Scene.v()
                .getMethod("<net.bytedance.security.app.pathfinder.testdata.CHATest\$Sub: java.lang.Object getSource()>"),
            "\$r0",
            UnknownType.v()
        )
        val sinkPtr = pt.allocLocal(
            Scene.v()
                .getMethod("<net.bytedance.security.app.pathfinder.testdata.CHATest\$ClassFlow: void callsink(java.lang.Object)>"),
            "r0",
            UnknownType.v()
        )
        Assertions.assertFalse(tsp.ctx.collectPropagation(srcPtr).contains(sinkPtr))

        val path =
            TaintPathFinder.bfsSearch(srcPtr, setOf(sinkPtr), tsp.ctx.variableFlowGraph, 256, "test")
        Assertions.assertNull(path)
    }

    @Test
    fun testStmt() {
        PLUtils.dumpClass("net.bytedance.security.app.pathfinder.testdata.ZipSlip")
        val clz = Scene.v().getSootClass("net.bytedance.security.app.pathfinder.testdata.ZipSlip")
        for (method in clz.methods) {
            println("method: ${method.shortSignature()}")
            for (unit in method.activeBody.units) {
                val stmt = unit as Stmt
                println("stmt=${stmt}")
                for (valueBox in stmt.useAndDefBoxes) {
                    println("${valueBox.value} --->${valueBox.value.javaClass.name}")
                }
                println("----")
            }
        }
    }

    @Test
    fun testBFS() {
        val src = newNode(1)
        var prev = newNode(2)
        val g = HashMap<PLPointer, Set<PLPointer>>()
        var last = prev
        g[src] = setOf(prev)
        for (i in 3 until 10) {
            last = newNode(i)
            g[prev] = setOf(last)
            prev = last
        }

        var path = TaintPathFinder.bfsSearch(src, setOf(last), g, 10, "test")
        assert(path!!.size == 9)
        println(path)
        path = TaintPathFinder.bfsSearch(src, setOf(last), g, 9, "test")
        assert(path == null)
        path = TaintPathFinder.bfsSearch(src, setOf(last), g, 3, "test")
        assert(path == null) //because of maxLen path, one path for test is discarded,currentLen=9,maxLen=9
    }

    @Test
    fun testBFSSameSourceAndSink() {
        val src = newNode(1)
        var prev = newNode(2)
        val g = HashMap<PLPointer, Set<PLPointer>>()
        var last: PLPointer
        g[src] = setOf(prev)
        for (i in 3 until 10) {
            last = newNode(i)
            g[prev] = setOf(last)
            prev = last
        }

        val path = TaintPathFinder.bfsSearch(src, setOf(src), g, 10, "test")
        assert(path!!.size == 1)

    }

    fun newNode(name: Int): PLPointer {
        return PLLocalPointer(TwoStagePointerAnalyze.getPseudoEntryMethod(), name.toString(), UnknownType.v())
    }

    @Test
    fun testlinkedlist() {
        val queue = LinkedList<Int>()
        queue.addLast(1)
        queue.addLast(2)
        queue.addLast(3)
        Assertions.assertEquals(listOf(1, 2, 3), queue.toList())
        val n = queue.pollFirst()
        Assertions.assertEquals(1, n)
        Assertions.assertEquals(listOf(2, 3), queue.toList())
        queue.pollFirst()
        Assertions.assertEquals(listOf(3), queue.toList())
        queue.pollFirst()
        Assertions.assertEquals(listOf<Int>(), queue.toList())
    }

}
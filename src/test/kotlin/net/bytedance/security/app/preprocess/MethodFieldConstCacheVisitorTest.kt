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
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import soot.Scene

internal class MethodFieldConstCacheVisitorTest
    : AnalyzePreProcessorTest() {
    private val ctx = PreAnalyzeContext()
    private val cache = MethodStmtFieldCache()

    init {
        val cam = AnalyzePreProcessor(10, ctx)
        cam.addMethodVisitor {
            MethodSSAVisitor()
        }
        runBlocking { cam.run() }
    }

    fun makeEmptyVisitor(): MethodFieldConstCacheVisitor {
        return MethodFieldConstCacheVisitor(ctx, cache, HashSet(), HashSet(), HashSet())
    }

    @Test
    fun testVisitMethodCallInterface() {
        PLUtils.dumpClass("net.bytedance.security.app.preprocess.testdata.Sub")
        val v = makeEmptyVisitor()
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object callInterface(net.bytedance.security.app.preprocess.testdata.Interface)>")
        v.visitMethod(m)
        assertEquals(
            v.cache.methodDirectRefs.map { it.key.signature }.toSortedSet().toList(), listOf(
                "<net.bytedance.security.app.preprocess.testdata.Interface: java.lang.Object methodImplementedInSub()>"
            )
        )
        assertEquals(
            v.cache.methodHeirRefs.map { it.key.signature }.toSortedSet().toList(), listOf(
                "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object methodImplementedInSub()>",
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object methodImplementedInSub()>"
            )
        )
    }

    @Test
    fun testVisitMethodCallMethodImplementedInParent() {
        PLUtils.dumpClass("net.bytedance.security.app.preprocess.testdata.Sub")
        val v = makeEmptyVisitor()
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object callMethodImplementedInParent()>")

        v.visitMethod(m)
        assert(v.cache.storeFieldRefs.isEmpty())
        println(v.cache.methodHeirRefs)
        assertTrue(v.cache.methodHeirRefs.isEmpty())
        assertTrue(v.cache.newInstanceRefs.isEmpty())
        assertTrue(v.cache.methodDirectRefs.size >= 3, "it depends on the java version")
        assertTrue(
            v.cache.methodDirectRefs.map { it.key.signature }.toSortedSet().contains(
                "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object methodImplementedInSub2()>"
            )
        )
        assertTrue(v.cache.loadFieldRefs.isEmpty())
        assertTrue(v.cache.storeFieldRefs.isEmpty())
    }

    @Test
    fun testVisitMethodField() {
        val v = makeEmptyVisitor()
        val m = Scene.v().getMethod("<net.bytedance.security.app.preprocess.testdata.Sub2: void <init>()>")
        v.visitMethod(m)
        assertEquals(
            v.cache.storeFieldRefs.map { it.key.signature }.toSortedSet().toList(), listOf<String>()
        )

        val v2 = MethodFieldConstCacheVisitor(
            ctx,
            cache,
            HashSet(),
            setOf("<net.bytedance.security.app.preprocess.testdata.Sub2: java.lang.Object field1>"),
            HashSet()
        )
        v2.visitMethod(m)
        assert(v.cache.loadFieldRefs.isEmpty())
        println(v.cache.methodDirectRefs)
        assertTrue(v.cache.methodDirectRefs.isNotEmpty()) //call base.<init>
        assertTrue(v.cache.methodHeirRefs.isEmpty())
        assertTrue(v.cache.newInstanceRefs.isEmpty())
        assertEquals(1, v.cache.storeFieldRefs.size)
        assertEquals(
            v2.cache.storeFieldRefs.map { it.key.signature }.toSortedSet().toList(),
            listOf<String>("<net.bytedance.security.app.preprocess.testdata.Sub2: java.lang.Object field1>")
        )
    }

    @Test
    fun testVisitMethodStaticField() {
        val v = MethodFieldConstCacheVisitor(
            ctx,
            cache,
            HashSet(),
            setOf("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String s>"),
            HashSet()
        )
        val m = Scene.v().getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: void <clinit>()>")
        v.visitMethod(m)
        assert(v.cache.loadFieldRefs.isEmpty())
        assertTrue(v.cache.methodDirectRefs.isEmpty())
        assertTrue(v.cache.methodHeirRefs.isEmpty())
        assertTrue(v.cache.newInstanceRefs.isEmpty())
        assertEquals(1, v.cache.storeFieldRefs.size)
        assertEquals(
            v.cache.storeFieldRefs.map { it.key.signature }.toSortedSet().toList(),
            listOf<String>("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String s>")
        )
    }


    @Test
    fun testVisitMethodLoadField() {
        val v = MethodFieldConstCacheVisitor(
            ctx,
            cache,
            HashSet(),
            setOf("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String s>"),
            HashSet()
        )
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object methodImplementedInSub()>")
        v.visitMethod(m)
        assert(v.cache.storeFieldRefs.isEmpty())
        assertTrue(v.cache.methodDirectRefs.isNotEmpty())
        assertTrue(v.cache.methodHeirRefs.isEmpty()) //Object.toString is ignored
        assertTrue(v.cache.newInstanceRefs.isEmpty())
        assertEquals(v.cache.loadFieldRefs.size, 1)
        assertEquals(
            v.cache.loadFieldRefs.map { it.key.signature }.toSortedSet().toList(),
            listOf<String>("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String s>")
        )
    }

    @Test
    fun testVisitMethodNewInstance() {
        val v = MethodFieldConstCacheVisitor(
            ctx,
            cache,
            HashSet(),
            setOf(),
            setOf(
                "net.bytedance.security.app.preprocess.testdata.Sub",
                "net.bytedance.security.app.preprocess.testdata.Sub2"
            )
        )
        val m = Scene.v().getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: void newInstance()>")
        v.visitMethod(m)
        assert(v.cache.storeFieldRefs.isEmpty())
//        assertTrue(v.c.methodDirectRefs.())
//        println(v.c.methodHeirRefs)
        assertTrue(v.cache.methodHeirRefs.isEmpty())
        assertTrue(v.cache.loadFieldRefs.isEmpty())
        assertEquals(2, v.cache.newInstanceRefs.size)
        assertEquals(
            v.cache.newInstanceRefs.map { it.key.className }.toSortedSet().toList(),
            listOf(
                "net.bytedance.security.app.preprocess.testdata.Sub",
                "net.bytedance.security.app.preprocess.testdata.Sub2"
            )
        )
    }

    @Test
    fun testSpecialInvoke() {
        val v = MethodFieldConstCacheVisitor(
            ctx,
            cache,
            HashSet(),
            setOf(),
            setOf(
            )
        )
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object allImplemented()>")
        v.visitMethod(m)
        assertTrue(v.cache.methodHeirRefs.isEmpty())
        assertEquals(
            "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object allImplemented()>",
            v.cache.methodDirectRefs.keys.first().signature
        )
    }
}
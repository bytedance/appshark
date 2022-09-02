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

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.DEBUG
import net.bytedance.security.app.Log
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.util.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import soot.Scene
import test.SootHelper
import test.TestHelper

internal open class AnalyzePreProcessorTest {
    private val ctx = PreAnalyzeContext()
    private val cam = AnalyzePreProcessor(10, ctx)

    init {
        Log.setLevel(DEBUG)
        SootHelper.initSoot(
            "ClassAndMethodHandlerTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata")
        )
    }

    @Test
    fun runCounter() {
        cam.addMethodVisitor { MethodCounter(ctx) }
        cam.addClassVisitor { ClassCounter(ctx) }
        runBlocking { cam.run() }
        println("ClassCounter: ${ctx.getClassCounter()}, MethodCounter: ${ctx.getMethodCounter()}")
        assert(ctx.getMethodCounter() > 0)
        assert(ctx.getClassCounter() > 0)
    }

    @Test
    fun runPattern() {
        cam.addMethodVisitor {
            MethodSSAVisitor()
        }.addMethodVisitor {
            MethodFieldConstCacheVisitor(
                ctx,
                MethodStmtFieldCache(),
                setOf("SubField1"), HashSet(), HashSet()
            )
        }
        runBlocking { cam.run() }
        println("ctx.patternMap=${ctx.constStringPatternMap}")
        assertEquals(1, ctx.constStringPatternMap.size)
    }

    @Test
    fun testCallGraph() {
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
        PLUtils.dumpClass("net.bytedance.security.app.preprocess.testdata.Sub")
        val m = Scene.v()
            .getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object callMethodImplementedInParent()>")
        val dms = ctx.callGraph.directCallGraph[m]
        val hms = ctx.callGraph.heirCallGraph[m]
        assertTrue(dms!!.size >= 3, "it depends on java version")
        assertTrue(hms!!.size >= 3, "it depends on java version")
        val m2 =
            Scene.v()
                .getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object callInterface(net.bytedance.security.app.preprocess.testdata.Interface)>")
        val rdms = ctx.callGraph.directCallGraph[m2]
        val rhms = ctx.callGraph.heirCallGraph[m2]
        assertEquals(1, rdms!!.size)
        assertEquals(3, rhms!!.size)
        println("caller=${m.signature}:\n direct callees=${dms} \n,heir callees=${hms}\n")
        println("callee=${m2.signature}:\n direct callers=${rdms} \n,heir callers=${rhms}\n")
    }

    @Test
    fun testCallGraph2() {
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
        val directs =
            ctx.callGraph.directCallGraph.filter { it.key.signature.indexOf("<net.bytedance.security.app.preprocess.testdata") == 0 }

        val heirs =
            ctx.callGraph.heirCallGraph.filter { it.key.signature.indexOf("<net.bytedance.security.app.preprocess.testdata") == 0 }
        assertTrue(ctx.callGraph.directCallGraph.isNotEmpty())
        assertTrue(ctx.callGraph.directReverseCallGraph.isNotEmpty())
        assertTrue(ctx.callGraph.heirCallGraph.isNotEmpty())
        assertTrue(ctx.callGraph.heirReverseCallGraph.isNotEmpty())
        println("directs=${Json.encodeToPrettyString(CallGraph.toStringMap(directs))}")
        println("heirs=${Json.encodeToPrettyString(CallGraph.toStringMap(heirs))}")
    }

    @Test
    fun runAllVisitor() {
        val ctx = PreAnalyzeContext()
        cam.addMethodVisitor {
            MethodSSAVisitor()
        }.addMethodVisitor { MethodCallbackVisitor(true) }
            .addMethodVisitor {
                MethodFieldConstCacheVisitor(
                    ctx,
                    MethodStmtFieldCache(),
                    HashSet(), HashSet(), HashSet()
                )
            }
        cam.addClassVisitor { ClassCounter(ctx) }
        runBlocking { cam.run() }
        println("cam finished")
    }


    @Test
    fun testChan() {
        val chan = Channel<Int>(5)
        var sum = 0
        val scope = CoroutineScope(Dispatchers.Default)
        val job = scope.launch {
            for (i in chan) {
                println(i)
                sum += i
            }
        }
        val job2 = scope.launch {
            for (i in 1..10) {
                chan.send(i)
            }
            chan.close()
        }
        runBlocking {
            job.join()
            job2.join()
        }
        assert(sum == 55)
    }
}
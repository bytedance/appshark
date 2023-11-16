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

import kotlinx.coroutines.*
import net.bytedance.security.app.PreAnalyzeContext
import org.junit.jupiter.api.Test
import soot.Scene
import soot.jimple.Stmt
import test.SootHelper
import test.TestHelper
import java.io.IOException
import kotlin.concurrent.thread
import kotlin.system.exitProcess

class SootConcurrentErrorTest {
    private val ctx = PreAnalyzeContext()
    private val cam = AnalyzePreProcessor(10, ctx)

    init {
        SootHelper.initSootForClasses(
            "SootConcurrentError",
            "${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/classes"
        )
        cam.addMethodVisitor {
            MethodSSAVisitor()
        }
        runBlocking { cam.run() }
    }

    @Test
    fun testlaunch() {
        runBlocking {
            val handler = CoroutineExceptionHandler { _, exception ->
                println("CoroutineExceptionHandler got $exception")
            }
            val job = GlobalScope.launch(handler) {
                val inner = launch { // all this stack of coroutines will get cancelled
                    launch {
                        launch {
                            throw IOException() // the original exception
                        }
                    }
                }
                try {
                    inner.join()
                } catch (e: CancellationException) {
                    println("Rethrowing CancellationException with original cause")
                    throw e // cancellation exception is rethrown, yet the original IOException gets to the handler
                }
            }
            job.join()
        }
    }

    @Test
    fun testResolveMethodConcurrentError() {
        val invokes = arrayOf(
            (Scene.v()
                .getMethod("<net.bytedance.security.app.preprocess.testdata.SuperNotExist: void <init>()>").activeBody.units.toArray()[1] as Stmt).invokeExpr,
            (
                    Scene.v()
                        .getMethod("<net.bytedance.security.app.preprocess.testdata.SuperNotExist2: void <init>()>").activeBody.units.toArray()[1] as Stmt
                    ).invokeExpr,
            (
                    Scene.v()
                        .getMethod("<net.bytedance.security.app.preprocess.testdata.SuperNotExist3: void <init>()>").activeBody.units.toArray()[1] as Stmt
                    ).invokeExpr,
            (
                    Scene.v()
                        .getMethod("<net.bytedance.security.app.preprocess.testdata.SuperNotExist4: void <init>()>").activeBody.units.toArray()[1] as Stmt
                    ).invokeExpr,
            (
                    Scene.v()
                        .getMethod("<net.bytedance.security.app.preprocess.testdata.SuperNotExist5: void <init>()>").activeBody.units.toArray()[1] as Stmt
                    ).invokeExpr,
        )
        val len = invokes.size
        for (i in 1..10) {
            val i2 = i
            thread(start = true) {
                Thread.sleep(1000)
                val m = invokes[i2 % len].method //resolve method may lead to concurrent error
                println(m.signature)
                println("i2=$i2.ref=${invokes[i2 % len].methodRef}")
            }
        }

        Thread.sleep(5000)
    }

    @Test
    fun testlaunchOOM() {
        runBlocking {
            val handler = CoroutineExceptionHandler { _, exception ->
                println("CoroutineExceptionHandler got $exception")
            }
            val job = GlobalScope.launch(handler) {
                val inner = launch { // all this stack of coroutines will get cancelled
                    launch {
                        launch {
                            val list = ArrayList<String>()
                            for (i in 1..1000000) {
                                list.add("12345".repeat(1000000))
                            }
                        }
                    }
                }
                try {
                    inner.join()
                } catch (e: java.lang.OutOfMemoryError) {
                    //oom should capture by handler
                    exitProcess(33)
                }
            }
            job.join()
        }
    }

}
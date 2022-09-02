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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import soot.Scene

internal class MethodCallbackVisitorTest : AnalyzePreProcessorTest() {

    @Test
    fun reflectionTest() {
        val m = Scene.v().getMethod("<net.bytedance.security.app.preprocess.testdata.Apple: void reflectionCall()>")

        MethodSSAVisitor.jimpleSSAPreprocess(m)
        val beforeSize = m.activeBody.units.size
        MethodCallbackVisitor(false).visitMethod(m)
        val afterSize = m.activeBody.units.size
        println(m.activeBody)
        assertEquals(beforeSize + 3, afterSize)
    }

    @Test
    fun reflectionTest2() {
        val m = Scene.v().getMethod("<net.bytedance.security.app.preprocess.testdata.Apple: void reflectionCall2()>")

        MethodSSAVisitor.jimpleSSAPreprocess(m)
        val beforeSize = m.activeBody.units.size
        MethodCallbackVisitor(false).visitMethod(m)
        val afterSize = m.activeBody.units.size
        assertEquals(beforeSize + 6, afterSize)
    }

    @Test
    fun testCLInit() {

        val m = Scene.v().getMethod("<net.bytedance.security.app.preprocess.testdata.Sub: void <init>()>")

        MethodSSAVisitor.jimpleSSAPreprocess(m)
        val beforeSize = m.activeBody.units.size
        MethodCallbackVisitor(false).visitMethod(m)
        val afterSize = m.activeBody.units.size
        assertEquals(beforeSize + 1, afterSize)
        println("after:")
        println(m.activeBody)
    }
}
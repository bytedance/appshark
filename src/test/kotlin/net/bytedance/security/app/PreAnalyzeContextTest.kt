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


package net.bytedance.security.app

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.rules.IRulesForContext
import org.junit.jupiter.api.Test
import test.SootHelper
import test.TestHelper

internal class PreAnalyzeContextTest() {
    init {
        SootHelper.initSoot(
            "ContextTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/preprocess/testdata")
        )
    }

    class Rules : IRulesForContext {
        override fun constStringPatterns(): Set<String> {
            return setOf("field_const_str")
        }

        override fun newInstances(): Set<String> {
            return setOf("android.webview.WebView")
        }

        override fun fields(): Set<String> {
            return setOf()
        }

    }

    @Test
    fun testRun() {
        val c = PreAnalyzeContext()
        runBlocking {
            c.createContext(Rules(), true)
        }
        assert(c.getMethodCounter() > 0)
        assert(c.getClassCounter() > 0)
        assert(c.constStringPatternMap.contains("field_const_str"))
    }
}
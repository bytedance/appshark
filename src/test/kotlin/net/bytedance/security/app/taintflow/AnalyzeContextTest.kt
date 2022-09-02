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

import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.pointer.PointerFactory
import org.junit.jupiter.api.Test
import soot.UnknownType
import test.SootHelper
import test.TestHelper

internal class AnalyzeContextTest {
    val ctx = AnalyzeContext(PointerFactory())

    init {
        SootHelper.initSoot(
            "AnalyzeContextTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/testdata")
        )
        PLUtils.createCustomClass()
    }

    @Test
    fun collectPropagation() {
        val p1 = newNode(1)
        ctx.collectPropagation(p1, true)
        ctx.collectPropagation(p1, true)
    }

    companion object {
        fun newNode(name: Int): PLPointer {
            return PLLocalPointer(TwoStagePointerAnalyze.getPseudoEntryMethod(), name.toString(), UnknownType.v())
        }
    }
}
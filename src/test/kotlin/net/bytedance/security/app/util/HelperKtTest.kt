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


package net.bytedance.security.app.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class HelperKtTest {
    @Test
    fun testMethodSignatureDestruction() {
        val fd = newFunctionSignature(
            "<net.bytedance.security.app.bvaa.ComponentRisk.IntentBridge: void IntentBridge2(java.lang.String,android.content.Class$1)>",
        )
        assertEquals(fd.className, "net.bytedance.security.app.bvaa.ComponentRisk.IntentBridge")
        assertEquals(fd.returnType, "void")
        assertEquals(fd.functionName, "IntentBridge2")
        assertEquals(fd.args, listOf("java.lang.String", "android.content.Class\$1"))
        assertEquals(fd.subSignature(), "void IntentBridge2(java.lang.String,android.content.Class\$1)")

        val fd2 = newFunctionSignature("<java.io.File: * <init>(*)>")
        assertEquals(fd2.returnType, "*")
        assertEquals(fd2.functionName, "<init>")
        assertEquals(fd2.args, listOf("*"))
    }

    @Test
    fun testStringArgIndex() {
        val s = "p0"
        assertEquals(s.argIndex(), 0)
    }

    @Test
    fun testGetMethodSigFromStr() {
        assertEquals(getMethodSigFromStr("xx<aa>xx"), "<aa>")
        assertEquals(getMethodSigFromStr("bbb"), "bbb")
        assertEquals(getMethodSigFromStr("bbb>xx<a"), "bbb>xx<a")
    }

    @Test
    fun newFieldSignature() {
        val fd =
            net.bytedance.security.app.util.newFieldSignature("<android.provider.VoicemailContract*: android.net.Uri *>")
        assertEquals(fd.className, "android.provider.VoicemailContract*")
        assertEquals(fd.fieldType, "android.net.Uri")
        assertEquals(fd.fieldName, "*")
    }
}
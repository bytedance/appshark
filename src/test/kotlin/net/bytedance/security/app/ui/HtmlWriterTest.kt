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


package net.bytedance.security.app.ui

import net.bytedance.security.app.RuleData
import net.bytedance.security.app.util.Json
import org.junit.jupiter.api.Test

val data = """
    {
    //it's ok to have a comment
    "unZipSlipDirectModeMode": {
      "traceDepth": 8,
      "desc": {
        "name": "unZipSlip" 
      },
      "entry": {
        "methods": [
          "<net.bytedance.security.app.ruleprocessor.testdata.ZipSlip: void UnZipFolder(java.lang.String,java.lang.String)>"
        ]
      },
      "source": {
        "Return": [
          "<java.util.zip.ZipEntry: java.lang.String getName()>"
        ]
      },
      "sink": {
        "<java.io.FileWriter: * <init>(*)>": {
          "TaintCheck": [
            "p*"
          ]
        },
        "<java.io.FileOutputStream: * <init>(*)>": {
          "TaintCheck": [
            "p*"
          ]
        }
      }
    }
  }
""".trimIndent()

internal class HtmlWriterTest {
    @Test
    fun testHtml() {
        val s = data
        val rules: Map<String, RuleData> = Json.decodeFromString(s)
        val desc = rules["unZipSlipDirectModeMode"]!!.desc
        val hw = HtmlWriter(desc)
        val s2 = hw.generateHtml()
        println(s2)
    }
}
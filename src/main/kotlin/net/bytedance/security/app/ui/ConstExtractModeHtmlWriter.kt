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

import kotlinx.html.TagConsumer
import kotlinx.html.a
import kotlinx.html.classes
import net.bytedance.security.app.Log
import net.bytedance.security.app.result.IVulnerability
import net.bytedance.security.app.result.OutputSecResults
import net.bytedance.security.app.result.VulnerabilityItem
import net.bytedance.security.app.rules.IRule
import soot.SootMethod
import soot.jimple.Stmt

/**
 * output for ConstStringMode and ConstNumberMode
 * @param constStr Matched string or number
 * @param stmt The statement that accesses the constant constStr
 * @param method The method which stmt belongs to
 */
class ConstExtractModeHtmlWriter(
    private val secResults: OutputSecResults,
    private val rule: IRule,
    val method: SootMethod,
    val stmt: Stmt,
    private val constStr: String
) : HtmlWriter(rule.desc), AddVulnerabilityAndSaveResult {

    override fun genContent(tag: TagConsumer<*>) {
        genVulInfo(tag)
        tag.a {
            classes = setOf(classVulnerabilityDetail)
            +constStr
        }
        genMethodWithHighlight(tag, method, setOf(stmt))
        genMethodJavaSource(tag, method)
    }

    override suspend fun addVulnerabilityAndSaveResultToOutput() {
        val stringList: MutableList<String> = ArrayList()
//        val apiSig = stmt.invokeExpr.methodRef.signature
        stringList.add(method.signature)
        stringList.add(stmt.toString())
        stringList.add(constStr)
        val tosUrl = saveContent(generateHtml(), htmlName)
        Log.logDebug("Write Vulnerability to $tosUrl")
        secResults.addOneVulnerability(
            VulnerabilityItem(
                rule,
                tosUrl,
                ConstExtractModeVulnerability(stringList, method.signature, constStr)
            )
        )
    }
}

class ConstExtractModeVulnerability(
    override val target: List<String>,
    override val position: String,
    val constValue: String
) :
    IVulnerability {
    override fun toDetail(): Map<String, Any> {
        return mapOf(
            "target" to target,
            "ConstValue" to constValue,
            "position" to position
        )
    }
}
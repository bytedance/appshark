/*
* Copyright 2021 ByteDance Inc.
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
 */
class APIModeHtmlWriter(
    private val secResults: OutputSecResults,
    val rule: IRule,
    val sm: SootMethod,
    val stmt: Stmt,
) : HtmlWriter(rule.desc), AddVulnerabilityAndSaveResult {
    override fun genContent(tag: TagConsumer<*>) {
        genVulInfo(tag)
        tag.a {
            classes = setOf(classVulnerabilityDetail)
            +"vulnerability postition:"
        }
        genMethodWithHighlight(tag, sm, setOf(stmt))
        genMethodJavaSource(tag, sm)
    }

    override suspend fun addVulnerabilityAndSaveResultToOutput() {
        val stringList: MutableList<String> = ArrayList()
        stringList.add(sm.signature)
        stringList.add(stmt.toString())
        val tosUrl = saveContent(generateHtml(), htmlName)
        Log.logDebug("Write ${rule.name} Vulner to $tosUrl")
        secResults.addOneVulnerability(VulnerabilityItem(rule, tosUrl, ApiModeVulnerability(stringList, sm.signature)))
    }
}

class ApiModeVulnerability(override val target: List<String>, override val position: String) : IVulnerability {
    override fun toDetail(): Map<String, Any> {
        return mapOf(
            "position" to position,
            "target" to target
        )
    }
}
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
import kotlinx.html.div
import net.bytedance.security.app.preprocess.CallSite
import net.bytedance.security.app.result.IVulnerability
import net.bytedance.security.app.result.OutputSecResults
import net.bytedance.security.app.result.VulnerabilityItem
import net.bytedance.security.app.rules.IRule
import soot.SootMethod

/**
 * output for FindClassMode
 */
class FindClassModeHtmlWriter(
    private val secResults: OutputSecResults,
    val rule: IRule,
    private val callMap: Set<CallSite>,
    private val vulnerabilityMethod: SootMethod
) : HtmlWriter(rule.desc), AddVulnerabilityAndSaveResult {
    override fun genContent(tag: TagConsumer<*>) {
        tag.div {
            genVulInfo(this.consumer)
            genVulnerabilityPosition(this.consumer)
            genInstance(this.consumer)
        }
    }


    private fun genVulnerabilityPosition(tag: TagConsumer<*>) {
        tag.a {
            classes = setOf(classVulnerabilityDetail)
            +"vulnerability position"
        }
        genMethodJimple(tag, vulnerabilityMethod)
        genMethodJavaSource(tag, vulnerabilityMethod)
    }

    private fun genInstance(tag: TagConsumer<*>) {
        tag.a {
            classes = setOf(classVulnerabilityDetail)
            +"instance position"
        }
        for (site in callMap) {
            genMethodWithHighlight(tag, site.method, setOf(site.stmt))
            genMethodJavaSource(tag, site.method)
        }
    }

    /**
     * 1. generate HTML  file
     * 2. add this vulnerability to the final report
     */
    override suspend fun addVulnerabilityAndSaveResultToOutput() {
        val stringList: MutableList<String> = ArrayList()
        stringList.add(vulnerabilityMethod.signature)
        val instantList: MutableList<String> = ArrayList()
        for (site in callMap) {
            instantList.add(site.method.signature + "{ " + site.stmt.toString() + " }")
        }
        val tosUrl = saveContent(generateHtml(), htmlName)
        secResults.addOneVulnerability(
            VulnerabilityItem(
                rule,
                tosUrl,
                FindClassModeVulnerability(stringList, vulnerabilityMethod.signature, instantList)
            )
        )
    }
}

class FindClassModeVulnerability(
    override val target: List<String>,
    override val position: String,
    private val instanceLocation: List<String>
) :
    IVulnerability {
    override fun toDetail(): Map<String, Any> {
        return mapOf(
            "target" to target,
            "InstanceLocation" to instanceLocation,
            "position" to position
        )
    }
}
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

import kotlinx.html.*
import kotlinx.html.stream.createHTML
import net.bytedance.security.app.EngineInfo
import net.bytedance.security.app.Log
import net.bytedance.security.app.RuleDescription
import net.bytedance.security.app.android.AndroidUtils
import net.bytedance.security.app.getConfig
import net.bytedance.security.app.web.DefaultVulnerabilitySaver
import soot.SootMethod
import soot.jimple.Stmt
import java.nio.charset.StandardCharsets
import java.time.LocalDateTime

interface AddVulnerabilityAndSaveResult {
    /**
     * 1. generate   HTML  file
     * 2. add this vulnerability to the final report
     */
    suspend fun addVulnerabilityAndSaveResultToOutput()
}

/**
html string generator for vulnerability report
 */
open class HtmlWriter(val desc: RuleDescription) {
    val htmlName = desc.name + ".html"
    fun generateHtml(): String {
        return try {
            createHTML(prettyPrint = false).html {
                genHead(this.consumer)
                genBody(this.consumer)
            }
        } catch (ex: Exception) {
            ex.printStackTrace()
            ""
        }
    }

    private fun genBody(tag: TagConsumer<*>) {
        tag.body {
            genContent(this.consumer)
        }
    }

    /**
     * Generate basic information
     */
    fun genVulInfo(tag: TagConsumer<*>) {
        tag.a {
            classes = setOf(classVulnerabilityDetail)
            +"vulnerability detail"
        }
        tag.pre {
            classes = setOf("java")
            code {
                +"Name: ${AndroidUtils.AppLabelName}\n"
                +"PackageName: ${AndroidUtils.PackageName}\n"
                +"ApplicationName: ${AndroidUtils.ApplicationName}\n"
                +"VersionName: ${AndroidUtils.VersionName}\n"
                +"VersionCode: ${AndroidUtils.VersionCode}\n"
                +"MinSdk: ${AndroidUtils.MinSdk}\n"
                +"TargetSdk: ${AndroidUtils.TargetSdk}\n"
                desc.wiki?.let {
                    +String.format("wiki: ")
                    a {
                        href = it
                        target = "_blank"
                        +it
                    }
                    +"\n"
                }
                +"name: ${desc.name}\n"
                +"category: ${desc.category}\n"
                +"detail: ${desc.detail}\n"
                if (getConfig().deobfApk.isNotEmpty()) {
                    +"deobfApk:"
                    a {
                        href = getConfig().deobfApk
                        target = "_blank"
                        +getConfig().deobfApk
                    }
                    +"\n"
                }
                desc.possibility?.let {
                    +"possibility: $it\n"
                }
                desc.model?.let {
                    +"model: $it\n"
                }
                desc.complianceCategory?.let {
                    +"complianceCategory: $it\n"
                }
                desc.complianceCategoryDetail?.let {
                    +"complianceCategoryDetail: $it\n"
                }
                +"scanTime: ${LocalDateTime.now()}\n"
                +"engineVersion:${EngineInfo.Version}\n"
            }
        }
    }

    /**
     *  need the concrete vulnerability to implement this method
     */
    open fun genContent(tag: TagConsumer<*>) {
    }

    companion object {
        const val classVulnerabilityDetail = "vulnerability-detail"
        private const val classCode = "code"
        const val classJava = "java"
        const val classBgheader1 = "bgheader1"
        const val classBgheader2 = "bgheader2"
        const val classHighlight = "highlightcode"
        fun genHead(tag: TagConsumer<*>) {
            tag.head {
                meta {
                    httpEquiv = "Content-Type"
                    content = "text/html"
                    charset = "UTF-8"
                }

                title("vulnerability scan result")
                link {
                    rel = "stylesheet"
                    href = "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/10.5.0/styles/default.min.css"
                }
                style {
                    unsafe {
                        raw(
                            """
                                .$classBgheader1{
                                background:#FFF;
                                color:#000;
                                }
                                .$classBgheader2{
                                background:#FFF;
                                color:#00F;
                                }
                        .background {
                         background-color: #272727;
		                 color: #ccc;
                        }
                        .$classCode {
                            background-color: #272727;
		                    color: #ccc;
                        }
                        .$classVulnerabilityDetail{
                        color:#F00;
                        }
                        .$classHighlight {
                        background:#FF0;
                        color:#00F;
                        }
                    
                """.trimIndent()
                        )
                    }
                }
                script { src = "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/10.5.0/highlight.min.js" }
                script { unsafe { raw("hljs.initHighlightingOnLoad();") } }
            }
        }

        /**
         *  generate the jimple body of method
         */
        fun genMethodJimple(tag: TagConsumer<*>, method: SootMethod) {
            genMethodWithHighlight(tag, method, HashSet())
        }

        /**
         * generate the jimple body of method with highlight stmt
         */
        fun genMethodWithHighlight(tag: TagConsumer<*>, method: SootMethod, hightSet: Set<Stmt>) {
            tag.pre {
                code {
                    classes = setOf("java")
                    +"${method.signature}{\n"
                    var i = 1
                    for (unit in method.activeBody.units) {
                        if (hightSet.contains(unit)) {
                            div {
                                classes = setOf(classHighlight)
                                +"$i: $unit"
                            }
                        } else {
                            +"$i: $unit\n"
                        }
                        i += 1
                    }
                    +"}\n"
                }
            }
        }


        /**
         * Generate Java source code for method, if it exists
         */
        fun genMethodJavaSource(tag: TagConsumer<*>, method: SootMethod) {
            val javaSourceCode = getJavaSource(method)
            if (javaSourceCode != null) {
                tag.div {
                    a {
                        classes = setOf(classVulnerabilityDetail)
                        +"java source code:"
                    }
                    tag.pre {
                        code {
                            classes = setOf("java")
                            +"class ${method.declaringClass.name}{\n"
                            +javaSourceCode
                            +"}\n"
                        }
                    }
                }
            }
        }
    }

    suspend fun saveContent(content: String, name: String): String {
        val tosUrl =
            DefaultVulnerabilitySaver.getVulnerabilitySaver()
                .saveVulnerability(content.toByteArray(StandardCharsets.UTF_8), name)
        Log.logDebug("htmlwriter write vulnerability to $tosUrl")
        return tosUrl
    }
}


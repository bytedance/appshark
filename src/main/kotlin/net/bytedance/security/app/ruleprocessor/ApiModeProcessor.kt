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


package net.bytedance.security.app.ruleprocessor

import net.bytedance.security.app.MethodFinder
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.preprocess.CallSite
import net.bytedance.security.app.result.OutputSecResults
import net.bytedance.security.app.rules.ApiModeRule
import net.bytedance.security.app.rules.IRule
import net.bytedance.security.app.ui.APIModeHtmlWriter
import net.bytedance.security.app.util.isFieldSignature
import net.bytedance.security.app.util.isMethodSignature
import soot.Scene

class ApiModeProcessor(val ctx: PreAnalyzeContext) : IRuleProcessor {
    override fun name(): String {
        return "APIMode"
    }

    override suspend fun process(rule: IRule) {
        if (rule !is ApiModeRule) {
            return
        }

        if (rule.apiPermission.isNotEmpty()) {
            val callSet = mutableSetOf<String>()

            rule.sink.keys.forEach { sinkRuleSig ->
                if (sinkRuleSig.isMethodSignature()) {
                    val methodSigSet = MethodFinder.checkAndParseMethodSig(sinkRuleSig)
                    callSet.addAll(methodSigSet.map { it.signature })
                } else if (sinkRuleSig.isFieldSignature()) {
                    val fieldSigSet = MethodFinder.checkAndParseFieldSignature(sinkRuleSig)
                    callSet.addAll(fieldSigSet.map { it.signature })
                }
            }
            apiPermissionToResults(rule.apiPermission, callSet)

        } else {
            rule.sink.keys.forEach { sinkRuleSig ->
                val callMap = when {
                    sinkRuleSig.isMethodSignature() -> {
                        val methodSigSet = MethodFinder.checkAndParseMethodSig(sinkRuleSig)
                        methodSigSet.map { ctx.findInvokeCallSite(it) }
                    }

                    sinkRuleSig.isFieldSignature() -> listOf(ctx.findFieldCallSite(sinkRuleSig))

                    else -> {
                        val matchedClasses = PLUtils.findMatchedChildClasses(setOf(sinkRuleSig))
                        Scene.v().getSootClassUnsafe(sinkRuleSig, false)?.let { matchedClasses.add(it) }
                        matchedClasses.map { ctx.findInstantCallSite(it.name) }
                    }
                }
                callMap.forEach { apiModeToHtml(rule, it) }
            }
        }
    }

    private suspend fun apiModeToHtml(rule: IRule, callMap: Set<CallSite>) {
        for (site in callMap) {
            APIModeHtmlWriter(OutputSecResults, rule, site.method, site.stmt)
                .addVulnerabilityAndSaveResultToOutput()
        }
    }

    private fun apiPermissionToResults(apiPermission: String, callSet: Set<String>) {
        OutputSecResults.ApiPermissionMapping[apiPermission] = callSet
    }
}

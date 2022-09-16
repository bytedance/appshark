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
        val sinkObject = rule.sink
        for (sinkRuleSig in sinkObject.keys) {
            if (sinkRuleSig.isMethodSignature()) {
                val methodSigSet = MethodFinder.checkAndParseMethodSig(sinkRuleSig)
                methodSigSet.forEach {
                    val callMap = ctx.findInvokeCallSite(it)
                    apiModeToHtml(rule, callMap)
                }

            } else if (sinkRuleSig.isFieldSignature()) {
                val callMap = ctx.findFieldCallSite(
                    sinkRuleSig
                )
                apiModeToHtml(rule, callMap)
            } else {
                val matchedClasses = PLUtils.findMatchedChildClasses(setOf(sinkRuleSig))
                val sinkClass = Scene.v().getSootClassUnsafe(sinkRuleSig, false)
                if (sinkClass != null) {
                    matchedClasses.add(sinkClass)
                }
                for (sc in matchedClasses) {
                    val callMap = ctx.findInstantCallSite(sc.name)
                    apiModeToHtml(rule, callMap)
                }
            }
        }
    }

    private suspend fun apiModeToHtml(rule: IRule, callMap: Set<CallSite>) {
        for (site in callMap) {
            APIModeHtmlWriter(OutputSecResults, rule, site.method, site.stmt).addVulnerabilityAndSaveResultToOutput()
        }
    }
}

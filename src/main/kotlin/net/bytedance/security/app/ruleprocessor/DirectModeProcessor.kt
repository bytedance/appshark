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


package net.bytedance.security.app.ruleprocessor

import net.bytedance.security.app.*
import net.bytedance.security.app.Log.logInfo
import net.bytedance.security.app.android.AndroidUtils
import net.bytedance.security.app.engineconfig.isLibraryClass
import net.bytedance.security.app.rules.DirectModeRule
import net.bytedance.security.app.rules.IRule
import net.bytedance.security.app.taintflow.TaintAnalyzer
import soot.Scene
import soot.SootMethod


open class DirectModeProcessor(ctx: PreAnalyzeContext) : TaintFlowRuleProcessor(ctx) {
    override fun name(): String {
        return "DirectMode"
    }

    override suspend fun process(rule: IRule) {
        if (rule !is DirectModeRule) {
            return
        }
        logInfo("${this.javaClass.name} process rule ${rule.name}")
        val entries = createEntries(rule)
        val taintRuleSourceSinkCollector = TaintRuleSourceSinkCollector(ctx, rule, entries)
        taintRuleSourceSinkCollector.collectSourceSinks()
        val analyzers = ArrayList<TaintAnalyzer>()
        createAnalyzers(rule, taintRuleSourceSinkCollector, entries, analyzers)
        this.collectAnalyzers(analyzers, rule)
    }

    open suspend fun createEntries(rule: DirectModeRule): List<SootMethod> {
        val entries: Set<SootMethod> =
            if (getConfig().doWholeProcessMode) {
                setOf(Scene.v().grabMethod(PLUtils.CUSTOM_CLASS_ENTRY))
            } else {
                val s = HashSet<SootMethod>()
                parseDirectEntry(rule.entry, s)
                s
            }
        return entries.toList()
    }

    open suspend fun createAnalyzers(
        rule: DirectModeRule,
        taintRuleSourceSinkCollector: TaintRuleSourceSinkCollector,
        entries: List<SootMethod>,
        analyzers: MutableList<TaintAnalyzer>
    ) {
        for (entry in entries) {
            if (!taintRuleSourceSinkCollector.entryHasValidSource(entry)) {
                continue
            }
            val analyzer = TaintAnalyzer(rule, entry, taintRuleSourceSinkCollector.analyzerData)
            analyzers.add(analyzer)
        }

    }

    /*
   entry:     "entry": {
     "methods": [
       "<*: android.webkit.WebResourceResponse shouldInterceptRequest(android.webkit.WebView,android.webkit.WebResourceRequest)>",
       "<*: android.webkit.WebResourceResponse shouldInterceptRequest(android.webkit.WebView,java.lang.String)>"
     ],
     "components": []
   }
    */
    private fun parseDirectEntry(entry: Entry?, entries: MutableSet<SootMethod>) {
        if (entry == null) {
            return
        }
        if (entry.ExportedCompos == true) {
            for (exportCompo in AndroidUtils.exportComponents) {
                if (AndroidUtils.compoEntryMap.containsKey(exportCompo)) {
                    val sootMethod = AndroidUtils.compoEntryMap[exportCompo]
                    entries.add(sootMethod!!)
                }
            }
        }
        if (entry.UseJSInterface == true) {
            jsInterfaceAsEntry(entries)
        }

        val components = entry.components
        if (components != null) {
            for (className in components) {
                val sc = Scene.v().getSootClassUnsafe(className, false)
                if (AndroidUtils.compoEntryMap.containsKey(sc)) {
                    val sootMethod = AndroidUtils.compoEntryMap[sc]
                    entries.add(sootMethod!!)
                }
            }
        }
        val entryMethods = entry.methods
        if (entryMethods != null) {
            for (entryMethodSig in entryMethods) {
                val methodSet = MethodFinder.checkAndParseMethodSig(entryMethodSig)
                for (method in methodSet) {
                    if (isLibraryClass(method.declaringClass.name)) {
                        continue
                    }
                    if (method.isConcrete) {
                        entries.add(method)
                    }
                }
            }
        }

        Log.logDebug("Direct Entry Size " + entries.size)
    }

    private fun jsInterfaceAsEntry(entries: MutableSet<SootMethod>) {
        if (ctx !is ContextWithJSBMethods) {
            return
        }
        for (sm in ctx.getJSBMethods()) {
            entries.add(sm)
        }
    }

}
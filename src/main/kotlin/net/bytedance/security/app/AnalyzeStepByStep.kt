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


package net.bytedance.security.app

import kotlinx.coroutines.*
import net.bytedance.security.app.Log.logInfo
import net.bytedance.security.app.result.OutputSecResults
import net.bytedance.security.app.ruleprocessor.RuleProcessorFactory
import net.bytedance.security.app.ruleprocessor.TaintFlowRuleProcessor
import net.bytedance.security.app.rules.RuleFactory
import net.bytedance.security.app.rules.Rules
import net.bytedance.security.app.taintflow.TaintAnalyzer
import net.bytedance.security.app.util.profiler
import soot.Scene
import soot.SootClass
import soot.options.Options
import java.io.File

class AnalyzeStepByStep {
    suspend fun loadRules(
        ruleList: List<String>,
    ): Rules {
        val rulePathList = ruleList.map {
            "${getConfig().rulePath}/$it"
        }.toList()
        val rules = Rules(rulePathList, RuleFactory())
        rules.loadRules()
        return rules
    }

    suspend fun parseRules(ctx: PreAnalyzeContext, rules: Rules): List<TaintAnalyzer> {
        val jobs = ArrayList<Job>()
        val analyzers = ArrayList<TaintAnalyzer>()
        val scope = CoroutineScope(Dispatchers.Default)
        for (r in rules.allRules) {
            val rp = RuleProcessorFactory.create(ctx, r.mode)
            val job = scope.launch(CoroutineName("parseRules-${r.name}")) {
                rp.process(r)
                if (rp is TaintFlowRuleProcessor) {
                    if (analyzers.size > getConfig().ruleMaxAnalyzer) {
                        logInfo("rule ${r.name} has too many rules: ${analyzers.size}, dropped")
                        return@launch
                    }
                    synchronized(analyzers) {
                        analyzers.addAll(rp.analyzers)
                    }

                }
            }
            jobs.add(job)
        }

        jobs.joinAll()
        logInfo("analyzers: ${analyzers.size}")
        profiler.setAnalyzers(analyzers)
        ctx.callGraph.clear()
        if (false) {
            PLUtils.dumpClass(PLUtils.CUSTOM_CLASS)
            var first = true
            for (a in analyzers) {
                if (first) {
                    println(a.dump())
                    first = false
                }
                println("entry:${a.entryMethod.signature}")
            }
        }
        return analyzers
    }

    suspend fun createContext(rules: Rules): PreAnalyzeContext {
        val preAnalyzeContext = PreAnalyzeContext()
        preAnalyzeContext.createContext(rules, getConfig().callBackEnhance)
        return preAnalyzeContext
    }

    enum class TYPE {
        CLASS, APK, AAR, JIMPLE
    }

    fun setExclude() {
        // reduce time
        val excludeList = ArrayList<String>()
        excludeList.add("java.*")
        excludeList.add("org.*")
        excludeList.add("sun.*")
        //        excludeList.add("android.*");
//        excludeList.add("androidx.*");
        Options.v().set_exclude(excludeList)
        // do not load body in exclude list
        Options.v().set_no_bodies_for_excluded(true)
        Scene.v().addBasicClass("android.os.Handler")
        Scene.v().addBasicClass("java.lang.Object[]", SootClass.HIERARCHY)
        Scene.v().addBasicClass("java.beans.Transient", SootClass.SIGNATURES)
        Scene.v().addBasicClass("java.time.ZoneRegion", SootClass.SIGNATURES)
    }

    fun initSoot(
        type: TYPE,
        targetPath: String,
        sdkPath: String,
        outPath: String
    ) {
        Log.logDebug("Init soot for $targetPath")

        if (type == TYPE.CLASS) {
            Options.v().set_src_prec(Options.src_prec_class)
            Options.v().set_process_dir(listOf(targetPath))
        } else if (type == TYPE.JIMPLE) {
            Options.v().set_src_prec(Options.src_prec_jimple)
            Options.v().set_process_dir(listOf(targetPath))
        } else if (type == TYPE.APK) {
            Options.v().set_src_prec(Options.src_prec_apk)

            // get android.jar path by sdk path and API level of apk
            val androidJarPath = Scene.v().getAndroidJarPath(sdkPath, targetPath)
            val processPathList: MutableList<String> = ArrayList()
            processPathList.add(targetPath)
            processPathList.add(androidJarPath)
            val platformFile = File(sdkPath)
            if (platformFile.exists() && platformFile.isDirectory) {
                for (jarFile in platformFile.listFiles()!!) {
                    if (jarFile.extension != "jar") {
                        continue //exclude non-jar file
                    }
                    processPathList.add(jarFile.absolutePath)
                }
            }
            Options.v().set_process_dir(processPathList)
            Options.v().set_force_android_jar(androidJarPath)
            Options.v().set_process_multiple_dex(true)
        } else if (type == TYPE.AAR) {
            Options.v().set_src_prec(Options.src_prec_class)
            Options.v().set_process_dir(listOf(targetPath))
        }
        // set the output dir
        Options.v().set_output_dir(outPath)

        // output jimple
        Options.v().set_output_format(Options.output_format_jimple)
        Options.v().set_allow_phantom_refs(true)
        Options.v().set_whole_program(true)
        Options.v().set_keep_line_number(false)
        Options.v().set_wrong_staticness(Options.wrong_staticness_ignore)
        Options.v().set_debug(false)
        Options.v().set_verbose(false)
        Options.v().set_validate(false)
//        Options.v().set_keep_line_number(true)
        setExclude()
        logInfo("loadNecessaryClasses")
        try {
            Scene.v().loadNecessaryClasses() // may take dozens of seconds
        } catch (ex: Exception) {
            Log.logErr("loadNecessaryClasses error: ${ex.message}")
            throw ex
        }
        logInfo("loadNecessaryClasses Done classes=${Scene.v().classes.size}")
    }


    suspend fun solve(ctx: PreAnalyzeContext, analyzers: List<TaintAnalyzer>) {
        if (getConfig().doWholeProcessMode) {
            solveWholeProcess(ctx, analyzers)
        } else {
            solveSliceMode(ctx, analyzers)
        }
        //generate report
        OutputSecResults.processResult(ctx)
    }

    private suspend fun solveWholeProcess(ctx: PreAnalyzeContext, analyzers: List<TaintAnalyzer>) {
        val p = WholeProcessAnalyzeWrapper(ctx, analyzers)
        p.run()
    }

    private suspend fun solveSliceMode(ctx: PreAnalyzeContext, analyzers: List<TaintAnalyzer>) {
        val p = SliceAnalyzeWrapper(ctx, analyzers)
        p.run()
    }
}

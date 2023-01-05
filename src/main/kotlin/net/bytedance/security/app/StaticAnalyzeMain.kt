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

import kotlinx.coroutines.runBlocking
import net.bytedance.security.app.Fragment.Companion.processFragmentEntries
import net.bytedance.security.app.Log.logInfo
import net.bytedance.security.app.android.AndroidUtils
import net.bytedance.security.app.android.AndroidUtils.loadDynamicRegisterReceiver
import net.bytedance.security.app.android.AndroidUtils.parseApk
import net.bytedance.security.app.engineconfig.EngineConfig
import net.bytedance.security.app.util.Json
import net.bytedance.security.app.util.profiler
import java.nio.file.Files
import java.nio.file.Paths


object StaticAnalyzeMain {
    @Throws(Exception::class)
    suspend fun startAnalyze(argumentConfig: ArgumentConfig) {
        val apkPath = argumentConfig.apkPath
        val v3 = AnalyzeStepByStep()
        val jadxPath = "${argumentConfig.configPath}/tools/jadx/bin/jadx"
        val apkNameTool = "${argumentConfig.configPath}/tools/ApkName.sh"

        logInfo("started...")
        profiler.startMemoryProfile()
        v3.initSoot(
            AnalyzeStepByStep.TYPE.APK,
            apkPath,
            "${argumentConfig.configPath}/tools/platforms",
            argumentConfig.outPath
        )
        logInfo("soot init done")
        PLUtils.createCustomClass()
        profiler.parseApk.start()
        parseApk(apkPath, jadxPath, argumentConfig.outPath, apkNameTool)
        logInfo("apk parse done")
        profiler.parseApk.end()

        profiler.preProcessor.start()
        val rules = v3.loadRules(argumentConfig.rules)
        logInfo("rules loaded")
        val ctx = v3.createContext(rules)
        profiler.preProcessor.end()


        if (getConfig().doWholeProcessMode) {
            PLUtils.createWholeProgramAnalyze(ctx)
        }
        loadDynamicRegisterReceiver(ctx)

        if (argumentConfig.supportFragment) {
            profiler.fragments.start()
            processFragmentEntries(ctx)
            profiler.fragments.end()
        }
        AndroidUtils.initLifeCycle()
        val analyzers = v3.parseRules(ctx, rules)
        v3.solve(ctx, analyzers)
        profiler.stopMemoryProfile()
    }
}

@Throws(Exception::class)
fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: java -jar appshark.jar  config.json5")
        return
    }
    val configPath = args[0]
    try {
        val configJson = String(Files.readAllBytes(Paths.get(configPath)))
        val argumentConfig: ArgumentConfig = Json.decodeFromString(configJson)
        cfg = argumentConfig
        ArgumentConfig.mergeWithDefaultConfig(argumentConfig)
        Log.setLevel(argumentConfig.logLevel)
        logInfo("welcome to appshark ${EngineInfo.Version}")
        getConfig().libraryPackage?.let {
            if (it.isNotEmpty()) {
                EngineConfig.libraryConfig.setPackage(it)
            }
        }
        runBlocking { StaticAnalyzeMain.startAnalyze(argumentConfig) }
    } catch (e: Exception) {
        e.printStackTrace()
    }
    Log.flushAndClose()
}

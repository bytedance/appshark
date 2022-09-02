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

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
class ArgumentConfig(
    @SerialName("CallBackEnhance")
    var callBackEnhance: Boolean = false,
    @SerialName("ManifestTrace")
    var manifestTrace: Int = 3,
    var apkPath: String,
    var configPath: String = "",
    //max pointer analysis time in second for each entry point
    var maxPointerAnalyzeTime: Int = 600,
    var javaSource: Boolean? = false,
    /**
     * If you have OOM problems, try lowering this value, such as 1, to save memory
     */
    var maxThread: Int = 2, //  Runtime.getRuntime().availableProcessors(),
    @SerialName("out") var outPath: String = "out",
    var rulePath: String = "",
    var rules: String = "",
    var supportFragment: Boolean = false,
    var logLevel: Int = INFO,
    var ruleMaxAnalyzer: Int = 5000, // If a rule produces too many Analyzers, the rule is discarded
    var deobfApk: String = "", // Decompiled APK download address
    var debugRule: String = "",
    /**
     * If you want accurate results, it's best to have full-program analyze mode,
     *   but it doesn't support large apps because it's too slow
     */
    var doWholeProcessMode: Boolean = false,
    var maxPathLength: Int = 32, // max taint flow path
    var skipAnalyzeNonRelatedMethods: Boolean = false, // skip analyze non-related methods with source and sinks ,if skip may lead to false negatives.
    var skipPointerPropagationForLibraryMethod: Boolean = true, //skip pointer propagation for library methods,if skip may lead to false negatives.
    //if exists, use it to replace Package in EngineConfig.json5
    var libraryPackage: List<String>? = null,
) {
    companion object {
        val defaultConfig: ArgumentConfig

        init {
            val wd = System.getProperty("user.dir")
            defaultConfig = ArgumentConfig(
                apkPath = "$wd/app.apk",
                outPath = "$wd/out",
                rules = "",
                javaSource = false,
                maxPointerAnalyzeTime = 600,
                maxThread = 4,
                manifestTrace = 3,
                callBackEnhance = true,
                doWholeProcessMode = false,
                deobfApk = "$wd/app.apk",
                logLevel = 1,
                configPath = "$wd/config",
                rulePath = "$wd/config/rules",
            )
        }

        fun mergeWithDefaultConfig(cfg: ArgumentConfig) {
            if (cfg.outPath.isEmpty()) {
                cfg.outPath = defaultConfig.outPath
            }
            if (cfg.configPath.isEmpty()) {
                cfg.configPath = defaultConfig.configPath
            }
            if (cfg.rulePath.isEmpty()) {
                cfg.rulePath = "${cfg.configPath}/rules"
            }
        }
    }
}

var cfg: ArgumentConfig? = null

/**
 *  ArgumentConfig is a global variable,it must be set as early as possible
 */
fun getConfig(): ArgumentConfig {
    if (cfg != null) {
        return cfg as ArgumentConfig
    }
    cfg = ArgumentConfig.defaultConfig
    return cfg!!
}
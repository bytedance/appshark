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


package net.bytedance.security.app.engineconfig

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.bytedance.security.app.Log
import net.bytedance.security.app.getConfig
import net.bytedance.security.app.util.Json
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths


fun isLibraryClass(className: String): Boolean {
    return EngineConfig.libraryConfig.isLibraryClass(className)
}

@Serializable
data class LibraryData(var Package: List<String>, val ExcludeLibraryContains: List<String>)

@Serializable
data class CallbackData(val param: Map<String, List<String>>, val enhanceIgnore: List<String>)

@Serializable
data class IgnoreListsData(
    val PackageName: List<String>? = null,
    val MethodName: List<String>? = null,
    //MethodSignature differs from MethodName in that the former is a complete function signature,
    val MethodSignature: List<String>? = null
)

@Serializable
data class FlowRuleData(
    val MethodName: Map<String, Map<String, IOData>>? = null,
    val MethodSignature: Map<String, Map<String, IOData>>? = null,
)

@Serializable
data class VariableFlowRuleData(
    val InstantDefault: Map<String, IOData>? = null,
    val InstantSelfDefault: Map<String, IOData>? = null,
    val StaticDefault: Map<String, IOData>? = null,
    val MethodName: Map<String, Map<String, IOData>>? = null,
    val MethodSignature: Map<String, Map<String, IOData>>? = null,
)

@Serializable
data class EngineConfigData(
    @SerialName("Library")
    val libraryConfig: LibraryData = LibraryData(listOf(), listOf()),
    @SerialName("Callback")
    val callbackConfig: CallbackData = CallbackData(mapOf(), listOf()),
    @SerialName("IgnoreList")
    val ignoreListConfig: IgnoreListsData = IgnoreListsData(),
    @SerialName("PointerFlowRule")
    val PointerPropagationConfig: FlowRuleData = FlowRuleData(),
    @SerialName("VariableFlowRule")
    val VariableFlowConfig: VariableFlowRuleData = VariableFlowRuleData(),
)

object EngineConfig {
    val callbackConfig: CallbackConfig
    val libraryConfig: LibraryConfig
    val IgnoreListConfig: IgnoreListsConfig
    val PointerPropagationConfig: PointerPropagationConfig
    val variableFlowConfig: VariableFlowConfig

    /**
     * Make sure that Config is properly initialized before accessing EngineConfig
     */
    init {
        val s = loadConfigOrQuit("${getConfig().configPath}/EngineConfig.json5")
        val engineConfigData = Json.decodeFromString<EngineConfigData>(s)
        callbackConfig = CallbackConfig(engineConfigData.callbackConfig)
        libraryConfig = LibraryConfig(engineConfigData.libraryConfig)
        IgnoreListConfig = IgnoreListsConfig(engineConfigData.ignoreListConfig)
        PointerPropagationConfig = PointerPropagationConfig(engineConfigData.PointerPropagationConfig)
        variableFlowConfig = VariableFlowConfig(engineConfigData.VariableFlowConfig)
    }

    fun loadConfigOrQuit(path: String): String {
        Log.logInfo("Load config file $path")
        val jsonStr = try {
            String(Files.readAllBytes(Paths.get(path)))
        } catch (e: IOException) {
            Log.logErr("read config file $path failed")
            throw Exception("read config file $path failed")
        }
        return jsonStr
    }
}
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


@file:Suppress("PropertyName")

package net.bytedance.security.app.result

import kotlinx.serialization.Serializable
import net.bytedance.security.app.Log
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.android.AndroidUtils
import net.bytedance.security.app.getConfig
import net.bytedance.security.app.result.model.*
import net.bytedance.security.app.util.Json
import net.bytedance.security.app.util.TaskQueue
import net.bytedance.security.app.util.profiler
import net.bytedance.security.app.util.uploadJsonResult
import kotlin.system.exitProcess

@Serializable
class Results {
    var AppInfo: AppInfo? = null
    var ManifestRisk: ManifestRisk? = null
    var SecurityInfo: MutableMap<String, MutableMap<String, SecurityRiskItem>> = HashMap()
    var ComplianceInfo: MutableMap<String, MutableMap<String, SecurityRiskItem>> = HashMap()
    var DeepLinkInfo: MutableMap<String, MutableSet<String>>? = null
    var HTTP_API: MutableList<HttpAPI>? = null
    var JsBridgeInfo: MutableList<JsBridgeAPI>? = null
    var BasicInfo: BasicInfo? = null
    var UsePermissions: Set<String>? = null
    var DefinePermissions: Map<String, String>? = null
    var Profile: String? = null
}

/**
 *  report output
 */
@Suppress("unused")
object OutputSecResults {

    private var Results = Results()

    private var BasicInfo = BasicInfo()
    private var DeepLinkInfo: MutableMap<String, MutableSet<String>> = HashMap()
    var AppInfo = AppInfo()
    var ManifestRisk = ManifestRisk()
    var APIList: MutableList<HttpAPI> = ArrayList()
    var JsBridgeList: MutableList<JsBridgeAPI> = ArrayList()
    var JSList: MutableList<String> = ArrayList()
    private var vulnerabilityItems = ArrayList<VulnerabilityItem>()

    fun init() {
        AppInfo.appsharkTakeTime = profiler.totalRange.takes
        AppInfo.classCount = profiler.ProcessMethodStatistics.availableClasses
        AppInfo.methodCount = profiler.ProcessMethodStatistics.availableMethods
        Results.AppInfo = AppInfo
        Results.ManifestRisk = ManifestRisk
        Results.DeepLinkInfo = DeepLinkInfo
        Results.HTTP_API = APIList
        Results.JsBridgeInfo = JsBridgeList
        Results.BasicInfo = BasicInfo
        BasicInfo.JSNativeInterface = JSList
        BasicInfo.ComponentsInfo = AndroidUtils.compoXmlMapByType
        initAppInfo()
    }

    fun setAppInfoOther(other: Map<String, String>) {
        if (AppInfo.otherInfo == null) {
            AppInfo.otherInfo = HashMap()
        }
        for (e in other) {
            AppInfo.otherInfo!![e.key] = e.value
        }
    }

    private fun initAppInfo() {
        AppInfo.AppName = AndroidUtils.AppLabelName
        AppInfo.PackageName = AndroidUtils.PackageName
        AppInfo.versionName = AndroidUtils.VersionName
        AppInfo.versionCode = AndroidUtils.VersionCode
        AppInfo.min_sdk = AndroidUtils.MinSdk
        AppInfo.target_sdk = AndroidUtils.TargetSdk
        profiler.AppInfo = AppInfo
    }

    private fun insertMani() {
        ManifestRisk.debuggable = AndroidUtils.debuggable
        ManifestRisk.allowBackup = AndroidUtils.allowBackup
        ManifestRisk.usesCleartextTraffic = AndroidUtils.usesCleartextTraffic
    }

    private fun insertPerm() {
        Results.UsePermissions = AndroidUtils.usePermissionSet
        Results.DefinePermissions = AndroidUtils.permissionMap
    }

    fun insertDeepLink(key: String, set: Set<String>) {
        if (set.isEmpty()) {
            return
        }
        val s = DeepLinkInfo.computeIfAbsent(key) { HashSet() }
        s.addAll(set)
    }

    private suspend fun addManifest(ctx: PreAnalyzeContext) {
        val manifestTaskQueue =
            TaskQueue<Pair<String, VulnerabilityItem>>("manifest", getConfig().getMaxPreprocessorThread()) { task, _ ->
                val t = TraceTask(ctx)
                t.addManifest(task.second, task.first)
            }
        val job = manifestTaskQueue.runTask()
        for (vulnerabilityItem in this.vulnerabilityItems) {
            val taintPath = vulnerabilityItem.data.target
            if (taintPath.isEmpty()) {
                continue
            }
            val sourceSig = taintPath[0].split("->").toTypedArray()[0]
            val pair = Pair(sourceSig, vulnerabilityItem)
            manifestTaskQueue.addTask(pair)
        }
        manifestTaskQueue.addTaskFinished()
        job.join()
    }

    /**
     * if vulnerability's hash are the  same, they are the same vulnerability
     * for one rule, different entry method may generate the same source and sink
     */
    private fun removeDup(): List<SecurityVulnerabilityItem> {
        val map = HashMap<String, SecurityVulnerabilityItem>()
        for (vulnerabilityItem in this.vulnerabilityItems) {
            val item = vulnerabilityItem.toSecurityVulnerabilityItem()
            val hash = item.hash!!
            map[hash] = item
        }
        return map.values.toList()
    }

    /**
     * group the results by the category
     */
    private fun groupResult(securityVulnerabilityItems: List<SecurityVulnerabilityItem>) {
        for (vulnerabilityItem in securityVulnerabilityItems) {
            val rule = vulnerabilityItem.rule!!
            val ruleDesc = rule.desc
            val category: String
            val subCategory: String = ruleDesc.name
            val m: MutableMap<String, MutableMap<String, SecurityRiskItem>>
            if (rule.isCompliance()) {
                category = ruleDesc.complianceCategory ?: "unknown"
                m = Results.ComplianceInfo
            } else {
                category = ruleDesc.category
                m = Results.SecurityInfo
            }
            val categoryMap = m.computeIfAbsent(category) { HashMap() }
            val item = categoryMap.computeIfAbsent(subCategory) {
                SecurityRiskItem(
                    ruleDesc.category,
                    ruleDesc.detail,
                    ruleDesc.model,
                    ruleDesc.name,
                    ruleDesc.possibility,
                    ArrayList(),
                    ruleDesc.wiki,
                    getConfig().deobfApk,
                    ruleDesc.level
                )
            }
            item.vulnerabilityItemMutableList.add(vulnerabilityItem)
        }
    }

    /**
     * Add all the added information. The final report is the Results field
     */
    suspend fun processResult(ctx: PreAnalyzeContext) {
        try {
            Results.Profile = profiler.finishAndSaveProfilerResult()
            init()
            insertPerm()
            insertMani()
            addManifest(ctx)
            groupResult(removeDup())
            val jsonName =
                "results_" + AndroidUtils.PackageName + "_" + java.lang.Long.toHexString(System.nanoTime() + (Math.random() * 100).toLong())
            val outputPath = getConfig().outPath + "/results.json"
            val profileOutputPath = getConfig().outPath + "/profile.json"
            profiler.processResult(Results)
            val s = Json.encodeToPrettyString(Results)
            PLUtils.writeFile(outputPath, s)
            PLUtils.writeFile(profileOutputPath, profiler.toString())
            Log.logErr("write json to $outputPath")
            uploadJsonResult("$jsonName.json", s)
        } catch (ex: Exception) {
            ex.printStackTrace()
            Log.logErr("ex=$ex,stack=\n${ex.stackTraceToString()}")
            exitProcess(21)
        }
    }

    @Synchronized
    fun addOneVulnerability(vulnerabilityItem: VulnerabilityItem) {
        this.vulnerabilityItems.add(vulnerabilityItem)
    }

    fun vulnerabilityItems(): List<VulnerabilityItem> {
        return this.vulnerabilityItems
    }

    //for test only
    fun testClearVulnerabilityItems() {
        this.vulnerabilityItems.clear()
    }
}

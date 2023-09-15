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


package net.bytedance.security.app.android

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.serializer
import net.bytedance.security.app.*
import net.bytedance.security.app.result.model.AnySerializer
import net.bytedance.security.app.util.Json
import soot.RefType
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.jimple.Constant
import soot.jimple.InstanceInvokeExpr
import soot.jimple.Stmt
import soot.jimple.infoflow.android.axml.AXmlHandler
import soot.jimple.infoflow.android.axml.AXmlNode
import soot.jimple.infoflow.android.axml.ApkHandler
import soot.jimple.infoflow.android.axml.parsers.AXML20Parser
import soot.jimple.infoflow.android.manifest.IAndroidApplication
import soot.jimple.infoflow.android.manifest.ProcessManifest
import soot.jimple.infoflow.android.manifest.binary.AbstractBinaryAndroidComponent
import soot.jimple.infoflow.android.manifest.binary.BinaryAndroidApplication
import soot.jimple.infoflow.android.resources.ARSCFileParser
import soot.jimple.infoflow.android.resources.ARSCFileParser.StringResource
import soot.jimple.infoflow.android.resources.LayoutFileParser
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import kotlin.system.exitProcess


/**
 * for convenience to recognize a particular structure during serialization
 */
interface ToMapSerializeHelper {
    fun toMap(): Map<String, Any>
}

@Serializable(with = ComponentDescriptionDataSerializer::class)
class ComponentDescription : ToMapSerializeHelper, Cloneable {
    var exported: Boolean = false
    var trace: List<String>? = null
    var stringMap: MutableMap<String, String> = HashMap()
    var otherMap: MutableMap<String, @Serializable(with = AnySerializer::class) Any> = HashMap()
    override fun toMap(): Map<String, Any> {
        val m = HashMap<String, Any>()

        m["exported"] = this.exported
        this.trace?.let {
            m["trace"] = this.trace!!
        }
        this.stringMap.forEach {
            m[it.key] = it.value
        }
        this.otherMap.forEach {
            m[it.key] = it.value
        }
        return m
    }

    public override fun clone(): ComponentDescription {
        val m2 = ComponentDescription()
        m2.exported = this.exported
        this.trace?.let {
            m2.trace = ArrayList(it)
        }
        m2.stringMap = HashMap(this.stringMap)
        m2.otherMap = HashMap(this.otherMap)
        return m2
    }
}


object ComponentDescriptionDataSerializer : KSerializer<ComponentDescription> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("ComponentDescription", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ComponentDescription) {
        val element = buildJsonObject {
            put("exported", value.exported)
            value.trace?.let {
                put("trace", Json.encodeToJsonElement(it))
            }
            value.stringMap.forEach {
                put(it.key, it.value)
            }
            value.otherMap.forEach {
                put(it.key, Json.encodeToJsonElement(AnySerializer, it.value))
            }
        }
        encoder.encodeSerializableValue(serializer(), element)
    }

    override fun deserialize(decoder: Decoder): ComponentDescription {
        error("deserialize is not supported")
    }
}


object AndroidUtils {
    var apkAbsPath: String? = null
    var JavaSourceDir: String? = null

    var dexToJavaProcess: Process? = null
    var jadxAbsPath: String? = null
    var resources: ARSCFileParser? = null
    var isApkParsed = false //

    @Suppress("unused")
    var exportDeeplinkCompos: MutableSet<SootClass> = HashSet()

    var exportComponents: MutableSet<SootClass> = HashSet()
    var unExportComponents: MutableSet<SootClass> = HashSet()
    var exportActivities: MutableSet<SootClass> = HashSet()
    var unExportActivities: MutableSet<SootClass> = HashSet()
    var exportServices: MutableSet<SootClass> = HashSet()
    var unExportServices: MutableSet<SootClass> = HashSet()
    var exportProviders: MutableSet<SootClass> = HashSet()
    var unExportProviders: MutableSet<SootClass> = HashSet()
    var exportReceivers: MutableSet<SootClass> = HashSet()
    var unExportReceivers: MutableSet<SootClass> = HashSet()

    var compoEntryMap: MutableMap<SootClass, SootMethod> = HashMap()

    var dummyToDirectEntryMap: MutableMap<SootMethod, SootMethod> = HashMap()

    // All Activities =>fake entry method
    var activityEntryMap: MutableMap<SootClass, SootMethod> = HashMap()

    // The key and value in compoEntryMap are swapped
    var entryCompoMap: MutableMap<SootMethod, SootClass> = HashMap()

    var compoXmlMapByType: MutableMap<String, MutableMap<String, ComponentDescription>> = HashMap()

    var GlobalCompoXmlMap: MutableMap<String, ComponentDescription> = HashMap()
    var layoutFileParser: LayoutFileParser? = null

    // user-defined permission
    var permissionMap: Map<String, String> = HashMap()
    var usePermissionSet: Set<String> = HashSet()

    // App info
    var PackageName: String = ""
    var ApplicationName: String = ""
    var AppLabelName: String = ""
    var VersionName: String = ""
    var VersionCode = 0
    var MinSdk = 0
    var TargetSdk = 0

    // Manifest risk
    var debuggable: Boolean? = null
    var allowBackup: Boolean? = null
    var usesCleartextTraffic: Boolean? = null

    private fun dexToJava(apkPath: String, outPath: String) {
        JavaSourceDir = outPath + PLUtils.JAVA_SRC
        val thread = Runtime.getRuntime().availableProcessors() / 2
        try {
            val start = System.currentTimeMillis()
            Log.logInfo("==========>Start dex to Java")
            val processBuilder = ProcessBuilder(
                "$jadxAbsPath.sh",
                jadxAbsPath,
                apkPath,
                JavaSourceDir, thread.toString()
            )
            Log.logInfo(processBuilder.command().toString())
            dexToJavaProcess = processBuilder.start()
            dexToJavaProcess?.waitFor(1800, TimeUnit.SECONDS)
            dexToJavaProcess?.destroy()
            dexToJavaProcess?.waitFor()
            Log.logInfo("Dex to Java Done " + (System.currentTimeMillis() - start) + "ms<==========")
        } catch (e: Exception) {
            e.printStackTrace()
        }
        Log.logInfo("write Java Source to $JavaSourceDir")
    }


    fun parseApk(apkPath: String, jadxPath: String, outPath: String, apkNameToolPath: String) {
        try {
            parseApkInternal(apkPath, jadxPath, outPath, apkNameToolPath)
        } catch (ex: Exception) {
            ex.printStackTrace()
        }
    }

    fun isWindows(): Boolean {
        val osName = System.getProperty("os.name")
        return osName != null && osName.startsWith("Windows")
    }

    /**
     * 1. Parse APK meta information
     * 2. Convert dex to Java
     * 3. Address manifest bugs
     */
    private fun parseApkInternal(apkPath: String, jadxPath: String, outPath: String, apkNameToolPath: String) {
        if (!isWindows()) {
            try {
                val processBuilder = ProcessBuilder(
                    apkNameToolPath,
                    apkPath
                )
                Log.logInfo(processBuilder.command().toString())
                val process = processBuilder.start()
                process.waitFor()
                val stream = process.inputStream
                val out = ByteArray(128)
                val ret = stream.read(out)
                if (ret > 0) {
                    AppLabelName = String(out, StandardCharsets.UTF_8)
                    AppLabelName = AppLabelName.trim { it <= ' ' }
                }
            } catch (e: Exception) {
                Log.logErr("$apkPath -> $outPath")
                e.printStackTrace()
            }
        }
        apkAbsPath = apkPath
        if (getConfig().javaSource == true) {
            Log.logDebug("Dex to java code")
            jadxAbsPath = jadxPath
            dexToJava(apkPath, outPath)
        }

        val targetAPK = File(apkAbsPath!!)
        Log.logDebug("Load resource")
        resources = ARSCFileParser()
        try {
            resources!!.parse(targetAPK.absolutePath)
        } catch (e: IOException) {
            e.printStackTrace()
        }
        Log.logDebug("Load manifest")
        val manifest: ProcessManifest = try {
            ProcessManifest(targetAPK, resources)
        } catch (e: Exception) {
            e.printStackTrace()
            try {
                val apk = ApkHandler(targetAPK)
                val manifestInputStream = apk.getInputStream("AndroidManifest.xml")
                val aXmlHandler = AXmlHandler(manifestInputStream)
                val manifests = aXmlHandler.getNodesWithTag("manifest")
                if (manifests.size > 0) {
                    val manifest = manifests[0]
                    PackageName = manifest.getAttribute("package").value as String
                    Log.logDebug("package $PackageName")
                }
            } catch (ioException: IOException) {
                ioException.printStackTrace()
                exitProcess(31)
            }
            return
        }

        getAppLabelNameIfNeeded(manifest)
        usePermissionSet = manifest.permissions
        permissionMap = getDefinedPermissions(manifest.manifest)
        Log.logDebug("use perm $usePermissionSet")
        Log.logDebug("def perm $permissionMap")
        PackageName = manifest.packageName
        Log.logDebug("package $PackageName")
        if (manifest.application.name != null) {
            ApplicationName = manifest.application.name
        }
        Log.logDebug("ApplicationName $ApplicationName")
        Log.logDebug("AppName $AppLabelName")
        manifest.versionName?.let {
            VersionName = manifest.versionName
        }
        Log.logDebug("VersionName $VersionName")
        VersionCode = manifest.versionCode
        Log.logDebug("VersionCode $VersionCode")
        MinSdk = manifest.minSdkVersion
        Log.logDebug("MinSdk $MinSdk")
        TargetSdk = manifest.targetSdkVersion
        Log.logDebug("TargetSdk $TargetSdk")
        layoutFileParser = LayoutFileParser(manifest.packageName, resources)
        layoutFileParser!!.parseLayoutFileDirect(apkPath)
        parseAllComponents(manifest)

        debuggable = manifest.application.isDebuggable      // 默认false
        allowBackup = manifest.application.isAllowBackup    // 默认true
        usesCleartextTraffic = manifest.application.isUsesCleartextTraffic ?: (TargetSdk < 28)  // API28以下默认true，否则默认false
        Log.logDebug("debuggable $debuggable")
        Log.logDebug("allowBackup $allowBackup")
        Log.logDebug("usesCleartextTraffic $usesCleartextTraffic")

        isApkParsed = true
    }

    private fun getAppLabelNameIfNeeded(manifest: ProcessManifest) {
        //return if empty
        if (AppLabelName != "") {
            return
        }
        AppLabelName = try {
            val v = (manifest.application as BinaryAndroidApplication).aXmlNode.getAttribute("label").value as Int
            println(v)
            val r = resources!!.findResource(v) as StringResource
            r.value
        } catch (e: Exception) {
            e.printStackTrace()
            Log.logErr("getAppLabelNameIfNeeded error")
            "unknown"
        }
    }

    fun getDefinedPermissions(manifestAxml: AXmlNode): Map<String, String> {
        val tmpPermissionMap: MutableMap<String, String> = HashMap()
        val usesPerms = manifestAxml.getChildrenWithTag("permission")
        val iterator = usesPerms.iterator()
        while (iterator.hasNext()) {
            val perm = iterator.next() as AXmlNode
            val name = perm.getAttribute("name")
            try {
                val protectionLevel = perm.getAttribute("protectionLevel")
                if (name != null) {
                    val permission = name.value as String
                    if (protectionLevel != null) {
                        val level = when (protectionLevel.value) {
                            is Int -> {
                                protectionLevel.value
                            }
                            is String -> {
                                try {
                                    (protectionLevel.value as String).toInt()
                                } catch (ex: Exception) {
                                    ex.printStackTrace()
                                    0
                                }
                            }
                            else -> {
                                0
                            }
                        }
                        var protection = PLUtils.LevelNormal
                        when (level) {
                            0 -> protection = PLUtils.LevelNormal
                            1 -> protection = PLUtils.LevelDanger
                            2 -> protection = PLUtils.LevelSig
                            3 -> protection = PLUtils.LevelSigOrSys
                        }
                        tmpPermissionMap[permission] = protection
                    } else {
                        tmpPermissionMap[permission] = PLUtils.LevelNormal
                    }
                }
            } catch (ex: Exception) {
                ex.printStackTrace()
            }
        }
        return tmpPermissionMap
    }

    fun loadDynamicRegisterReceiver(ctx: PreAnalyzeContext) {
        val broadcastRecSig =
            "<android.content.Context: void registerReceiver*(android.content.BroadcastReceiver,android.content.IntentFilter)>"
        val broadcastRecName = "registerReceiver"
        val methodSet = MethodFinder.checkAndParseMethodSig(broadcastRecSig)
        val invokeMap = ctx.methodDirectRefs
        for (method in methodSet) {
            val callerSet = invokeMap[method] ?: continue
            for (sm in callerSet) {
                if (!sm.method.isConcrete) {
                    continue
                }
                for (unit in sm.method.retrieveActiveBody().units) {
                    val stmt = unit as Stmt
                    if (!stmt.containsInvokeExpr()) {
                        continue
                    }
                    val invokeExpr = stmt.invokeExpr
                    if (invokeExpr.argCount < 2) {
                        continue
                    }
                    if (invokeExpr is InstanceInvokeExpr) {
                        if (invokeExpr.getMethodRef().name == broadcastRecName) {
                            val arg0 = invokeExpr.getArgs()[0]
                            if (arg0 is Constant) {
                                continue
                            }
                            if (Scene.v().orMakeFastHierarchy.canStoreType(
                                    arg0.type,
                                    RefType.v("android.content.BroadcastReceiver")
                                )
                            ) {
                                val className = arg0.type.toString()
                                if (className == "android.content.BroadcastReceiver") {
                                    continue
                                }
                                val sc = Scene.v().getSootClassUnsafe(className, false)
                                if (sc != null) {
//                                    PLLog.logErr("add BroadcastReceiver: "+className+" => "+stmt.toString());
                                    exportReceivers.add(sc)
                                    exportComponents.add(sc)
                                    val broadcastReceiver = ComponentDescription()
                                    broadcastReceiver.stringMap["DynamicBroadcastReceiver"] = className
                                    broadcastReceiver.stringMap["RegisteredMethod"] = sm.method.signature
                                    broadcastReceiver.stringMap["RegisteredStmt"] = stmt.toString()
                                    broadcastReceiver.exported = true
                                    if (!compoXmlMapByType.containsKey("exportedReceivers")) {
                                        compoXmlMapByType["exportedReceivers"] = HashMap()
                                    }
                                    compoXmlMapByType["exportedReceivers"]!![className] = broadcastReceiver
                                    GlobalCompoXmlMap[className] = broadcastReceiver
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @Synchronized
    fun buildEntryCompoMap() {
        for ((key, value) in compoEntryMap) {
            entryCompoMap[value] = key
        }
    }

    fun initLifeCycle() {
        Log.logInfo("exportActivities=$exportActivities")
        for (compo in exportActivities) {
            val entry =
                PLUtils.createComponentEntry(LifecycleConst.ActivityClass, compo, LifecycleConst.ActivityMethods)
            compoEntryMap[compo] = entry
            activityEntryMap[compo] = entry
        }
        for (compo in unExportActivities) {
            val entry =
                PLUtils.createComponentEntry(LifecycleConst.ActivityClass, compo, LifecycleConst.ActivityMethods)
            compoEntryMap[compo] = entry
            activityEntryMap[compo] = entry
        }
        for (compo in exportReceivers) {
            val entry = PLUtils.createComponentEntry(
                LifecycleConst.BroadcastReceiverClass,
                compo,
                LifecycleConst.BroadcastReceiverMethods
            )
            compoEntryMap[compo] = entry
        }
        for (compo in unExportReceivers) {
            val entry = PLUtils.createComponentEntry(
                LifecycleConst.BroadcastReceiverClass,
                compo,
                LifecycleConst.BroadcastReceiverMethods
            )
            compoEntryMap[compo] = entry
        }
        for (compo in exportServices) {
            val entry = PLUtils.createComponentEntry(LifecycleConst.ServiceClass, compo, LifecycleConst.ServiceMethods)
            compoEntryMap[compo] = entry
        }
        for (compo in unExportServices) {
            val entry = PLUtils.createComponentEntry(LifecycleConst.ServiceClass, compo, LifecycleConst.ServiceMethods)
            compoEntryMap[compo] = entry
        }
        for (compo in exportProviders) {
            val entry =
                PLUtils.createComponentEntry(LifecycleConst.ContentProviderClass, compo, LifecycleConst.ProviderMethods)
            compoEntryMap[compo] = entry
        }
        for (compo in unExportProviders) {
            val entry =
                PLUtils.createComponentEntry(LifecycleConst.ContentProviderClass, compo, LifecycleConst.ProviderMethods)
            compoEntryMap[compo] = entry
        }
        buildEntryCompoMap()
    }


    fun parseResAXml(fileName: String): AXmlNode? {
        return parseResAXmlHandler(fileName)?.document?.rootNode
    }

    fun parseResAXmlHandler(fileName: String): AXmlHandler? {
        val apkF = File(apkAbsPath!!)
        if (!apkF.exists()) {
            Log.logDebug("file '$apkAbsPath' does not exist!")
            return null
        }
        try {
            ZipFile(apkF).use { archive ->
                val entries = archive.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement() as ZipEntry
                    val entryName = entry.name
                    if (entryName == fileName) {
                        archive.getInputStream(entry).use { inputStream ->
                            return AXmlHandler(inputStream, AXML20Parser())
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.logErr("Error when looking for XML resource files in apk $apkAbsPath")
        }
        return null
    }

    private fun parseComponent(
        c: AbstractBinaryAndroidComponent,
        exportedCompoSet: MutableSet<SootClass>,
        unExportedCompoSet: MutableSet<SootClass>,
        type: String
    ): Boolean {
        val aXmlNode = c.aXmlNode
        val xmlInfo = ComponentDescription()
        var isExportedCompo = c.isExported
        if (c.isEnabled) {
            val childNodes = aXmlNode.getChildrenWithTag("intent-filter")
            //refer https://developer.android.com/guide/topics/manifest/activity-element#exported
            if (childNodes.isNotEmpty() && !aXmlNode.hasAttribute("exported")) {
                isExportedCompo = true
            }
        }

        if (isExportedCompo) {
            if (aXmlNode.hasAttribute("permission")) {
                val perm = aXmlNode.getAttribute("permission").value as String
                Log.logDebug("perm $perm")
                if (permissionMap.containsKey(perm)) {
                    Log.logDebug("level " + permissionMap[perm])
                    if (permissionMap[perm] != PLUtils.LevelNormal) {
                        isExportedCompo = false
                    }
                } else {
                    isExportedCompo = false
                }
            }
        }
        val classNameObj = c.nameString ?: return false //  aXmlNode.getAttribute("name")?.value
        val className: String = classNameObj
        val sc = Scene.v().getSootClassUnsafe(className, false) ?: return false
        val key = aXmlNode.toString().replace("\"", "")
        val itemArr: MutableList<Map<String, List<String>>> = ArrayList()

        for (node in aXmlNode.children) {
            val itemKey = node.toString().replace("\"", "")
            val item: MutableMap<String, List<String>> = HashMap()
            itemArr.add(item)
            val itemValueList: MutableList<String> = ArrayList()
            item[itemKey] = itemValueList
            for (itemNode in node.children) {
                itemValueList.add(itemNode.toString().replace("\"", ""))
            }
        }
        xmlInfo.otherMap[key] = Json.encodeToJsonElement(itemArr)
        val compoKey: String
        if (isExportedCompo) {
            compoKey = "exported$type"
            exportedCompoSet.add(sc)
            exportComponents.add(sc)
            xmlInfo.exported = true
        } else {
            compoKey = "unExported$type"
            unExportedCompoSet.add(sc)
            unExportComponents.add(sc)
            xmlInfo.exported = false
        }
        if (!compoXmlMapByType.containsKey(compoKey)) {
            compoXmlMapByType[compoKey] = HashMap()
        }
        compoXmlMapByType[compoKey]!![className] = xmlInfo
        GlobalCompoXmlMap[className] = xmlInfo
        return isExportedCompo
    }

    private fun parseAllComponents(manifests: ProcessManifest) {
        for (aXmlNode in manifests.activities) {
            parseComponent(aXmlNode, exportActivities, unExportActivities, "Activities")
        }
        for (aXmlNode in manifests.broadcastReceivers) {
            parseComponent(aXmlNode, exportReceivers, unExportReceivers, "Receivers")
        }
        for (aXmlNode in manifests.contentProviders) {
            parseComponent(aXmlNode, exportProviders, unExportProviders, "Providers")
        }
        for (aXmlNode in manifests.services) {
            parseComponent(aXmlNode, exportServices, unExportServices, "Services")
        }
    }

    /**
    layoutId corresponding to R.layout.XXX
    the return may be null.
     */
    fun findFragmentsInLayout(layoutId: Int): Set<SootClass>? {
        val r = resources!!.findResource(layoutId)
        val name = r.resourceName
        //        System.out.println(String.format("getResourceName:%s", name));
        val key = "res/layout/$name.xml"
        val fragments = layoutFileParser!!.fragments
        return fragments[key]
    }
}

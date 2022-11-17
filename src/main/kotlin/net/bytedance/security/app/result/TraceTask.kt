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


package net.bytedance.security.app.result

import net.bytedance.security.app.Log
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.android.AndroidUtils
import net.bytedance.security.app.android.ComponentDescription
import net.bytedance.security.app.getConfig
import net.bytedance.security.app.ui.TaintPathModeVulnerability
import net.bytedance.security.app.util.isFieldSignature
import soot.Scene
import soot.SootClass
import soot.SootMethod
import java.util.*

/**
add manifest field for vulnerability
 */
class TraceTask(
    val ctx: PreAnalyzeContext,
) {
    private fun getValidManifestEntry(
        entryMethod: SootMethod,
        validClassSet: MutableSet<SootClass>
    ): ComponentDescription? {

        val sc = entryMethod.declaringClass
        if (sc != null && !validClassSet.contains(sc)) {
            validClassSet.add(sc)
            val className = sc.name
            return AndroidUtils.GlobalCompoXmlMap[className]
        }

        return null
    }

    /**
     *  add manifest for vulnerability
     */
    fun addManifest(vulnerabilityItem: VulnerabilityItem, sourceSig: String) {
        //no need to process field's manifest
        if (sourceSig.isFieldSignature()) {
            return
        }
        val sourceMethod = Scene.v().getMethod(sourceSig)
        var componentJsonObj: ComponentDescription? = null
        var entryClassName: String? = null
        if (vulnerabilityItem.data !is TaintPathModeVulnerability) {
            return
        }
        val entryMethod = vulnerabilityItem.data.entryMethod
        if (AndroidUtils.entryCompoMap.containsKey(entryMethod)) {
            val entryClass = AndroidUtils.entryCompoMap[entryMethod]
            Log.logDebug(" class $entryClass")
            entryClassName = entryClass!!.name
            if (AndroidUtils.GlobalCompoXmlMap.containsKey(entryClassName)) {
                componentJsonObj = AndroidUtils.GlobalCompoXmlMap[entryClassName]
            }
        }

        if (componentJsonObj != null) {
            Log.logDebug("find direct entry ")
            val componentJsonObj2 = componentJsonObj.clone()

            val path = ctx.callGraph.queryPath(entryMethod, sourceMethod, 16).map { it.signature }.toMutableList()
            if (path.size > 0) {
                path.removeAt(0) //Using real component names instead of our own constructed  virtual entry method
            }
            path.add(0, entryClassName)
            componentJsonObj2.trace = path
            Log.logDebug("addTrace detailsJsonMap=$vulnerabilityItem,sourceMethodSig=$sourceSig")
            vulnerabilityItem.data.addManifest(componentJsonObj2)
            Log.logDebug("results $vulnerabilityItem\n")
        } else {
            val validClassSet: MutableSet<SootClass> = HashSet()
            val entryCallerSet: MutableSet<SootMethod> = HashSet()
            ctx.callGraph.queryTopEntryNoCustomMain(
                false,
                sourceMethod,
                getConfig().manifestTrace * 3 / 2,
                entryCallerSet
            )
            entryCallerSet.add(sourceMethod)
            val manifestList = LinkedList<ComponentDescription>()
            for (method in entryCallerSet) {
                Log.logDebug("Entry $method")
                val manifest2 = getValidManifestEntry(method, validClassSet)
                if (manifest2 != null) {
                    val manifest = manifest2.clone()
                    val path = ctx.callGraph.queryPath(method, sourceMethod, getConfig().manifestTrace)
                        .map { it.signature }
                    if (path.isNotEmpty()) {
                        manifest.trace = path
                        if (manifest.exported) {
                            manifestList.addFirst(manifest)
                        } else {
                            manifestList.addLast(manifest)
                        }
                    }
                }
            }
            for (jsonObject in manifestList) {
                vulnerabilityItem.data.addManifest(jsonObject)
            }
        }
        Log.logDebug("results $vulnerabilityItem\n")
    }
}

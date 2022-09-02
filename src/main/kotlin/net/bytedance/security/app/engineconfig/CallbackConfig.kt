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

import net.bytedance.security.app.Log
import soot.Scene
import soot.SootClass
import java.util.concurrent.atomic.AtomicBoolean


/**
 * callback config in memory
 */
class CallbackConfig(val callbackData: CallbackData) {
    private var param: Map<SootClass, List<String>> = HashMap()
    var enhanceIgnore: List<String> = ArrayList()
    private var isInit = AtomicBoolean(false)

    init {
        this.enhanceIgnore = callbackData.enhanceIgnore
    }

    @Synchronized
    fun getCallBackConfig(): Map<SootClass, List<String>> {
        if (!isInit.get()) {
            loadConfig()
        }
        return param
    }

    @Synchronized
    private fun loadConfig() {
        //double check
        if (isInit.get()) {
            return
        }
        if (Scene.v().classes.size == 0) {
            throw Exception("soot not init")
        }
        parseRules()
        isInit.set(true)
    }

    private fun parseRules() {
        param = getOneItem(callbackData.param)
    }

    private fun getOneItem(
        param: Map<String, List<String>>,
    ): MutableMap<SootClass, MutableList<String>> {
        val classMap = HashMap<SootClass, MutableList<String>>()
        // "android.view.View$OnClickListener":["*"],
        // "java.lang.Runnable":["void run()"],
        for ((className, methodArgArray) in param) {
            val sc = Scene.v().getSootClassUnsafe(className, false) ?: continue

            val methodList: MutableList<String> = ArrayList()
            if (methodArgArray.size == 1 && methodArgArray[0] == "*") {
                for (sootMethod in sc.methods) {
                    if (sootMethod.isConstructor || sootMethod.isStaticInitializer) {
                        continue
                    }
                    methodList.add(sootMethod.subSignature)
                }
            } else {
                for (method in methodArgArray) {
                    methodList.add(method)
                }
            }
            classMap[sc] = methodList
            val subClasses = HashSet<SootClass>()
            getSubCLassExcludeLib(sc, subClasses)
            if (subClasses.isEmpty()) {
                continue
            }
            for (subClass in subClasses) {
                val list = classMap.computeIfAbsent(subClass) { ArrayList() }
                list.addAll(methodList)
            }
        }
        Log.logDebug("Expand param callback rules " + classMap.keys.size)
        return classMap
    }

    fun getSubCLassExcludeLib(sc: SootClass, subClasses: MutableSet<SootClass>) {
        val subClassSet = if (sc.isInterface) {
            Scene.v().orMakeFastHierarchy.getAllImplementersOfInterface(sc)

        } else {
            Scene.v().orMakeFastHierarchy.getSubclassesOf(sc)
        }
        if (subClassSet == null) {
            return
        }
        for (sootClass in subClassSet) {
            if (subClasses.contains(sootClass)) {
                continue
            }
            val className = sootClass.name
            if (!EngineConfig.libraryConfig.isLibraryClass(className)) {
                subClasses.add(sootClass)
            }
            getSubCLassExcludeLib(sootClass, subClasses)
        }
    }
}

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


/**
functions such as hot patches, do not need to be analyzed.
 */
class IgnoreListsConfig(ignoreListData: IgnoreListsData) {

    private var packageNameSet: HashSet<String> = HashSet()
    private var methodNameSet: HashSet<String> = HashSet()
    private var methodSigSet: HashSet<String> = HashSet()

    init {
        ignoreListData.PackageName?.forEach {
            packageNameSet.add(it)
        }
        ignoreListData.MethodName?.forEach {
            methodNameSet.add(it)
        }
        ignoreListData.MethodSignature?.forEach { methodSigSet.add(it) }

    }

    fun isInIgnoreList(className: String, methodName: String, methodSig: String): Boolean {
        return containsPackageName(className) || containsMethodName(methodName) || containsMethodSig(methodSig)
    }

    private fun containsPackageName(className: String): Boolean {
        if (packageNameSet.contains(className)) {
            return true
        }
        for (ignorePackageName in packageNameSet) {
            if (className.startsWith(ignorePackageName)) {
                return true
            }
        }
        return false
    }

    private fun containsMethodName(methodName: String): Boolean {
        return methodNameSet.contains(methodName)
    }

    private fun containsMethodSig(methodSig: String): Boolean {
        return methodSigSet.contains(methodSig)
    }

}
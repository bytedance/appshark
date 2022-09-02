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

class LibraryConfig(val libraryData: LibraryData) {

    private fun isInExcludeLibrary(className: String): Boolean {
        for (excludeContain in libraryData.ExcludeLibraryContains) {
            if (className.contains(excludeContain)) {
                return true
            }
        }
        return false
    }

    fun isLibraryClass(className: String): Boolean {
        for (packageName in libraryData.Package) {
            //If it's library. It is necessary to continue to check
            // whether it belongs to the whitelist which needs to be analyzed
            if (className.startsWith(packageName)) {
                // Only those not on the whitelist are considered libraries
                if (!isInExcludeLibrary(className)) {
                    return true
                }
            }
        }
        return false
    }

    fun isLibraryMethod(methodSig: String): Boolean {
        val className = methodSig.substring(1)
        return isLibraryClass(className)
    }

    fun setPackage(packages: List<String>) {
        libraryData.Package = packages
    }

}
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


package net.bytedance.security.app.taintflow

import net.bytedance.security.app.engineconfig.EngineConfig
import net.bytedance.security.app.engineconfig.isLibraryClass
import soot.SootMethod

object DefaultMethodAnalyzeMode : IMethodAnalyzeMode {
    override fun methodMode(method: SootMethod): MethodAnalyzeMode {
        if (EngineConfig.IgnoreListConfig.isInIgnoreList(method.declaringClass.name, method.name, method.signature)) {
            return MethodAnalyzeMode.Skip
        } else if (isLibraryClass(method.declaringClass.name)) {
            return MethodAnalyzeMode.Obscure
        } else if (!method.hasActiveBody()) {
            return MethodAnalyzeMode.Obscure
        }
        return MethodAnalyzeMode.Analyze
    }

}
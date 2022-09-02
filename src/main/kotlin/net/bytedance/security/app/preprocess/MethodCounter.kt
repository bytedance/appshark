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


package net.bytedance.security.app.preprocess

import net.bytedance.security.app.Log
import net.bytedance.security.app.PreAnalyzeContext
import soot.SootMethod

class MethodCounter(val ctx: PreAnalyzeContext) : MethodVisitor {
    override fun visitMethod(method: SootMethod) {
//        PLLog.logInfo("visit visitMethod: ${method.signature}")
        if (!method.isConcrete) {
            return
        }
        val n = ctx.addMethodCounter()
        if (n % 1000 == 0) {
            Log.logInfo("processed $n methods")
        }
    }

    override fun collect(visitors: List<MethodVisitor>) {
        //do nothing
    }
}
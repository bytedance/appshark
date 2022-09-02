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

import net.bytedance.security.app.Log.logErr
import soot.SootMethod

/**
call back of
 */
class MethodCallbackVisitor(private val callbackEnhance: Boolean) : MethodVisitor {
    override fun visitMethod(method: SootMethod) {
        if (!method.hasActiveBody()) {
            return
        }
        try {
            doVisit(method)
        } catch (e: Exception) {
            logErr("this exception only related to preprocess of method $method")
            e.printStackTrace()
        }
    }

    /**
     * 1. patch for <clinit>
     * 2. callback from config file
     * 3. patchFindviewByIdForWebview
     * 4.Reflection
     */
    private fun doVisit(method: SootMethod) {
        Patch.patchCLInit(method)
        val before = method.activeBody.units.size
        MethodPatch.processCallback(
            method,
            callbackEnhance
        )
        val after = method.activeBody.units.size
        if (after > before) {
            //if there are changes, generate jimple ssa again
            MethodSSAVisitor.jimpleSSAPreprocess(method)
        }
    }

    override fun collect(visitors: List<MethodVisitor>) {
        //do nothing
    }
}
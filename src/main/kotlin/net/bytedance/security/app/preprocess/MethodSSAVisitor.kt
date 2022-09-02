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
import soot.Body
import soot.PackManager
import soot.SootMethod
import soot.shimple.Shimple
import soot.shimple.ShimpleBody

/**
 *
 */
class MethodSSAVisitor : MethodVisitor {
    override fun visitMethod(method: SootMethod) {
        if (!method.isConcrete) {
            return
        }
        try {
            jimpleSSAPreprocess(method)
        } catch (e: Exception) {
            logErr("JimpPreprocess error: $e,for method:${method.signature}")
        }
    }

    override fun collect(visitors: List<MethodVisitor>) {
        //
    }


    companion object {
        fun jimpleSSAPreprocess(sootMethod: SootMethod): Body {
            val sBody: ShimpleBody
            val body = sootMethod.retrieveActiveBody()
            if (body is ShimpleBody) {
                sBody = body
                if (!sBody.isSSA) sBody.rebuild()
            } else {
                sBody = Shimple.v().newBody(body)
            }
            sootMethod.activeBody = sBody
            PackManager.v().getPack("stp").apply(sBody)
            PackManager.v().getPack("sop").apply(sBody)
            sootMethod.activeBody = sBody.toJimpleBody()
            return sootMethod.activeBody
        }

    }
}
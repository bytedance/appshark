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


package net.bytedance.security.app.util

import net.bytedance.security.app.Log
import kotlin.reflect.full.memberProperties

@Suppress("unused")
fun dataClassToString(instance: Any) {
    val sb = StringBuilder()
    sb.append("data class ${instance::class.qualifiedName} (")
    var prefix = ""
    instance::class.memberProperties.forEach {
        sb.append(prefix)
        prefix = ","
        val call = try {
            it.getter.call(instance)
        } catch (ex: Exception) {
            ""
        }

        sb.append("${it.name} = $call")
    }
    sb.append(")")
    Log.logDebug(sb.toString())
} 

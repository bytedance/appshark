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


package net.bytedance.security.app.pointer

import net.bytedance.security.app.taintflow.TwoStagePointerAnalyze

import net.bytedance.security.app.util.profiler
import soot.SootField
import soot.SootMethod
import soot.Type
import soot.Value


/**
 * Corresponds to object in pointer analyze. For example, File file=new File()
 */
class PLObject(var classType: Type, private val where: Any, private val site: Int, val signature: String) {
    val isPseudoObj: Boolean
        get() = where is SootMethod && where == TwoStagePointerAnalyze.getPseudoEntryMethod()

    init {
        profiler.newObject(signature)
    }

    override fun toString(): String {
        return this.longSignature()
    }

    override fun equals(other: Any?): Boolean {
        return if (other is PLObject) {
            signature == other.signature
        } else false
    }

    override fun hashCode(): Int {
        return signature.hashCode()
    }

    fun longSignature(): String {
        val sig = when (where) {
            is SootMethod -> {
                where.signature
            }
            is SootField -> {
                where.signature
            }
            else -> {
                throw Exception("getObjectSignature unknown where $where")
            }
        }
        return "obj{$sig:$site=>${classType}}"
    }

    companion object {

        fun getObjectSignature(
            classType: Type,
            where: Any, //SootMethod or SootField
            v: Value?,
            site: Int
        ): String {
            var value = ""
            if (v != null) {
                value = v.toString()
            }
            val sig = when (where) {
                is SootMethod -> {
                    where.shortSignature()
                }
                is SootField -> {
                    where.shortSignature()
                }
                else -> {
                    throw Exception("getObjectSignature unknown where $where")
                }
            }
            if (shortNameEnable) {
                return "obj{${sig}:$site=>${classType.shortName()}}"
            }
            return "obj{$sig:$site=>${classType.shortName()}::{$value}}"
        }
    }
}

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

import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.util.profiler
import soot.SootField
import soot.SootMethod
import soot.Type
import soot.jimple.Constant

/**
 * to save memory
 */
const val shortNameEnable = true

/**
 * Pointer to variables and constants generated during analysis
 */
class PLLocalPointer : PLPointer {
    var method: SootMethod
    var variable: String
    var id: String

    override val ptrType: Type
    var constant: Constant? = null
    fun setConst(constant: Constant?) {
        this.constant = constant
    }

    constructor(method: SootMethod, localName: String, origType: Type, sig: String) {
        this.method = method
        variable = localName

        ptrType = PointerFactory.typeWrapper(origType)

        id = sig
        profiler.newPtrLocal(id)
    }

    constructor(method: SootMethod, localName: String, origType: Type) {
        this.method = method
        variable = localName
        // We have a rule that all arrays are converted to 1-dimensional arrays.
        ptrType = PointerFactory.typeWrapper(origType)
        id = getPointerLocalSignature(method, localName)
        profiler.newPtrLocal(id)
    }

    val isParam: Boolean
        get() = variable.startsWith(PLUtils.PARAM)

    val isConstStr: Boolean
        get() = variable.startsWith(PLUtils.CONST_STR)

    val isThis: Boolean
        get() = variable == PLUtils.THIS_FIELD
    val isLocal: Boolean
        get() = !isParam && !isThis

    /**
     * name of this variable,for example r0,$r0,
     * if PLPtrLocal is a constant,then it's the value of the constant
     */
    val variableName: String
        get() {
            if (!isConstStr) {
                return variable
            }
            return variable.slice(PLUtils.CONST_STR.length until variable.length)
        }

    override fun toString(): String {
        return this.signature()
    }

    override fun equals(other: Any?): Boolean {
        return if (other is PLLocalPointer) {
            id == other.id
        } else false
    }

    override fun hashCode(): Int {
        return id.hashCode()
    }

    override fun signature(): String {
        return getLocalLongSignature(method, variable)
    }

    companion object {
        fun getLocalLongSignature(method: SootMethod, localName: String): String {
            return "${method.signature}->$localName"
        }

        fun getPointerLocalSignature(method: SootMethod, localName: String): String {
            if (shortNameEnable) {
                return "${method.shortSignature()}->$localName"
            }
            return getLocalLongSignature(method, localName)
        }
    }
}

fun SootMethod.shortSignature(): String {
    if (shortNameEnable) {
        return "${this.declaringClass.shortName}:${this.name}" // soot remove some numbers which are actually not really needed (https://github.com/soot-oss/soot/commit/554dbc3815b12165086850b27517a8d1fda72488)
    }
    return this.signature
}

fun SootField.shortSignature(): String {
    if (shortNameEnable) {
        return "${this.declaringClass.shortName}:${this.name}" // soot remove some numbers which are actually not really needed (https://github.com/soot-oss/soot/commit/554dbc3815b12165086850b27517a8d1fda72488)
    }
    return this.signature
}

fun Type.shortName(): String {
    if (shortNameEnable) {
        return this.toString().split(".").last() + this.number.toString()
    }
    return this.toString()
}
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


import net.bytedance.security.app.util.profiler
import soot.SootField
import soot.Type

/**
 * pointer points to the field of an instance
 * obj is the instance.
 */
@Suppress("ConvertSecondaryConstructorToPrimary")
class PLPtrObjectField : PLPointer {
    override var ptrType: Type


    var obj: PLObject
    var field: String

    /**
     * there is only one case that sootField is null, the field is @data
     */
    var sootField: SootField?
    var id: String

    constructor(
        obj: PLObject,
        field: String,
        type: Type,
        sootField: SootField?,
        signature: String,
    ) {
        profiler.newPtrObjectField(signature)

        this.ptrType = type
        this.obj = obj
        this.field = field
        this.sootField = sootField
        this.id = signature
    }

    override fun toString(): String {
        return signature()
    }

    override fun equals(other: Any?): Boolean {
        return if (other is PLPtrObjectField) {
            id == other.id
        } else false
    }

    override fun hashCode(): Int {
        return id.hashCode()
    }

    override fun signature(): String {
        return PointerFactory.getObjectFieldSignature(obj, ptrType, field)
    }

}

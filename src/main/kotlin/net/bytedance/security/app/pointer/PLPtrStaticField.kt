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
 * pointer representation of a static field
 */
class PLPtrStaticField(val field: SootField) :
    PLPointer {
    override val ptrType: Type get() = this.field.type


    override fun toString(): String {
        return field.signature
    }

    init {
        profiler.newPtrStaticField(field.signature)
    }

    override fun equals(other: Any?): Boolean {
        return if (other is PLPtrStaticField) {
            field == other.field
        } else false
    }

    override fun hashCode(): Int {
        return field.hashCode()
    }

    override fun signature(): String {
        return field.signature
    }
}

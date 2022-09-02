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


package net.bytedance.security.app.rules

import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.util.argIndex

class TaintPosition(arg: String) {

    val position: Int

    init {
        position = if (arg == PLUtils.THIS_FIELD || arg == BASE) {
            This
        } else if (arg == RETURN || arg == RET) {
            Return
        } else if (arg == BASE_DATA) {
            ThisAllField
        } else if (arg == MATCH_ALL) {
            AllArgument
        } else if (arg.startsWith("p")) {
            arg.argIndex()
        } else {
            throw Exception("unknown taint point $arg")
        }
    }

    fun isConcreteArgument(): Boolean {
        return position >= 0
    }

    companion object {
        //all the argument
        const val AllArgument = -1

        //return of a method
        const val Return = -2

        //this pointer of a method
        const val This = -3

        //all field of this pointer
        const val ThisAllField = -4

        const val BASE = "@this"
        const val BASE_DATA = "@this.data"

        //    const val RET_DATA = "ret.data"
        const val RET = "ret"
        const val RETURN = "return"
        const val MATCH_ALL = "p*"
    }

}
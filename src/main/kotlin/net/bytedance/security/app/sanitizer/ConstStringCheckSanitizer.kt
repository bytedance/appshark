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


package net.bytedance.security.app.sanitizer

import net.bytedance.security.app.pointer.PLLocalPointer

/**
 * if these const strings are referenced, they are considered to satisfy the sanitizer condition
 */
class ConstStringCheckSanitizer(val constStrings: List<PLLocalPointer>) :
    ISanitizer {
    override fun matched(ctx: SanitizeContext): Boolean {
        for (c in constStrings) {
            if (ctx.ctx.pt.ptrIndexMap.contains(c.id)) {
                return true
            }
        }
        return false
    }
}
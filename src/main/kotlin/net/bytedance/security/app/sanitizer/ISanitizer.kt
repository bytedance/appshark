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
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.taintflow.AnalyzeContext

//肯定是单线程的工作模式
class SanitizeContext(val ctx: AnalyzeContext, val src: PLPointer, val sink: Set<PLLocalPointer>)

interface ISanitizer {
    /**
     * whether the ctx matches a sanitizer
     */
    fun matched(ctx: SanitizeContext): Boolean
}
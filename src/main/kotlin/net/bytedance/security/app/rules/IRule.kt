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

import net.bytedance.security.app.RuleDescription

/**
 *Abstract interfaces to all rules, because the engine supports many modes, and modes can be extended as needed
 */
interface IRule {
    /**
     * SliceMode,apiMode etc
     */
    val mode: String

    /**
     *
     *  {
     * "name": "DESEncryption",
     * "category": "CryptoRisk",
     * "wiki": "",
     * "detail": "some description",
     * "possibility": "4",
     * "model": "low"
     * }
     */
    val desc: RuleDescription

    //name of rule
    val name: String
    fun isCompliance(): Boolean {
        return desc.category == "ComplianceInfo"
    }
}
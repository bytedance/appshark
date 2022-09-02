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

import org.junit.jupiter.api.Test

internal class DebugKtTest {

    @Test
    fun toSorted() {
        val s = setOf(
            "<CustomClass: void Main_Entry_SmpReceiver3(java.lang.String[])>",
            " <CustomClass: void Main_Entry_AudioNotificationManager_AudioNotificationBroadcastReceiver(java.lang.String[])>",
            " <CustomClass: void Main_Entry_FakeIconWidgetProvider(java.lang.String[])>",
            " <CustomClass: void Main_Entry_TTSearchWidgetWordProvider(java.lang.String[])>",
            " <CustomClass: void Main_Entry_AlipayResultActivity(java.lang.String[])>"
        )
        val s2 = toSorted(s)
        val s3 = s.toSortedSet()
        println(s2)
        println(s3)

    }
}
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


package test

import net.bytedance.security.app.MethodFinder
import net.bytedance.security.app.sanitizer.SanitizerFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

object TestHelper {
    /**
     * @param className net.Bytedance.Security.App.ContextTest
     * @return $wd/SRC/test/kotlin/com/security
     */
    fun getTestClassSourceFileDirectory(className: String): String {
        val path = System.getProperty("user.dir")
        val ss = className.split(".")
        var subPath = ss.slice(0..ss.size - 2).joinToString("/")
        return "$path/src/test/kotlin/$subPath"
    }

    fun appsharkInit() {
        MethodFinder.clearCache()
        SanitizerFactory.clearCache()
    }

    @Test
    fun testGetTestClassSourceFileDirectory() {
        val path = System.getProperty("user.dir")
        assertEquals(
            "$path/src/test/kotlin/net/bytedance/security/app",
            getTestClassSourceFileDirectory("net.bytedance.security.app.ContextTest")
        )
    }
}
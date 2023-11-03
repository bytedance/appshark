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


package net.bytedance.security.app.java

val testdata = """ 
package net.bytedance.security.app.pathfinder.testdata;

public class CHATest {
    static public class Base {
        public Object getSource() {
            return "";
        }
    }

    static public class Sub extends Base {
        @Override
        public Object getSource() {
            return Taint.source();
        }
    }

    static public class ClassFlow {
        void callsink(Object arg) {
            Taint.sink(arg);
        }

        Object f(Base b) {
            return b.getSource();
        }

        void flow() {
            Base b = new Base();
            Object obj = f(b);
            callsink(obj);
        }
    }

}
""".trimIndent()

internal class JavaASTTest {
//    @Test
//    fun testParseJavaSource() {
//        try {
//            JavaAST.parseJavaSource("net.bytedance.security.app.pathfinder.testdata.CHATest", testdata)
//            assert(JavaAST.ASTMap.isNotEmpty())
//            println(Json.encodeToString(JavaAST.ASTMap))
//        } catch (ex: Exception) {
//            ex.printStackTrace()
//            assert(false) {
//                error("exception")
//            }
//        }
//
//    }
}


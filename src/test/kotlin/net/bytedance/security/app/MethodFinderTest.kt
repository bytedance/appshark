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


package net.bytedance.security.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import test.SootHelper
import test.TestHelper

internal class MethodFinderTest {
    init {
        SootHelper.initSoot(
            "MethodFinderTest",
            listOf("${TestHelper.getTestClassSourceFileDirectory(this.javaClass.name)}/preprocess/testdata")
        )
    }

    @Test
    fun checkAndParseMethodSig() {
        //1. Full function signature
        var sig = "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object methodImplementedInSub()>"
        var methods = MethodFinder.checkAndParseMethodSig(sig)

        assertEquals(methods.map { it.signature }.toList(), listOf(sig))

        //2. Base
        sig = "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object methodImplementedInSub()>"
        methods = MethodFinder.checkAndParseMethodSig(sig)

        //Sub2 is not included because methodImplementedInSub is not implemented in Sub2
        assertEquals(
            methods.map { it.signature }.toSortedSet().toList(),
            listOf(
                sig,
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object methodImplementedInSub()>"
            ).toSortedSet().toList()
        )

        //3. method name is *
        sig = "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object *()>"
        methods = MethodFinder.checkAndParseMethodSig(sig)

        assertEquals(
            methods.map { it.signature }.toSortedSet().toList(),
            listOf(
                "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object allImplemented()>",
                "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object methodImplementedInSub()>",
                "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object methodImplementedInSub2()>",
                "<net.bytedance.security.app.preprocess.testdata.Base: void <init>()>",
                "<net.bytedance.security.app.preprocess.testdata.Sub2: java.lang.Object allImplemented()>",
                "<net.bytedance.security.app.preprocess.testdata.Sub2: java.lang.Object methodImplementedInSub2()>",
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object allImplemented()>",
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object methodImplementedInSub()>",
            ).toSortedSet().toList()
        )

        //4. class name is *
        sig = "<*: java.lang.Object methodImplementedInSub()>"
        methods = MethodFinder.checkAndParseMethodSig(sig)
        assertEquals(
            methods.map { it.signature }.toSortedSet().toList(),
            listOf(
                "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object methodImplementedInSub()>",
                "<net.bytedance.security.app.preprocess.testdata.Interface: java.lang.Object methodImplementedInSub()>",
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object methodImplementedInSub()>"
            )
        )

        //5. The return value is *, which is not an exact match
        sig = "<net.bytedance.security.app.preprocess.testdata.Base: * methodImplementedInSub()>"
        methods = MethodFinder.checkAndParseMethodSig(sig)
        assertEquals(
            methods.map { it.signature }.toSortedSet().toList(), listOf(
                "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object methodImplementedInSub()>",
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object methodImplementedInSub()>"
            ).toSortedSet().toList()
        )

        //6. The parameter is *, which is not an exact match
        sig = "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object callInterface(*)>"
        methods = MethodFinder.checkAndParseMethodSig(sig)
        assertEquals(
            methods.map { it.signature }.toSortedSet().toList(), listOf(
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object callInterface(net.bytedance.security.app.preprocess.testdata.Interface)>"
            ).toSortedSet().toList()
        )

        //7. The function name partially matches
        sig = "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object callInterface*(*)>"
        methods = MethodFinder.checkAndParseMethodSig(sig)
        assertEquals(
            methods.map { it.signature }.toSortedSet().toList(), listOf(
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object callInterface(net.bytedance.security.app.preprocess.testdata.Interface)>",
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object callInterfaceNoImplementation(net.bytedance.security.app.preprocess.testdata.InterfaceNonExist)>"
            ).toSortedSet().toList()
        )

        //8. method that  doesn't exist
        sig = "<net.bytedance.security.app.preprocess.testdata.NotExist: java.lang.Object callInterface*(*)>"
        methods = MethodFinder.checkAndParseMethodSig(sig)
        assertEquals(
            methods.map { it.signature }.toSortedSet().toList(), listOf<String>()
        )

    }

    @Test
    fun checkAndParseFieldSignature() {
        var sig = "<*: * field1>"
        var fields = MethodFinder.checkAndParseFieldSignature(sig)
        assertEquals(
            fields.map { it.signature }.toSortedSet().toList(), listOf(
                "<net.bytedance.security.app.preprocess.testdata.Base: java.lang.Object field1>",
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.Object field1>",
                "<net.bytedance.security.app.preprocess.testdata.Sub2: java.lang.Object field1>"
            ).toSortedSet().toList()
        )
        sig = "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String *>"
        fields = MethodFinder.checkAndParseFieldSignature(sig)
        assertEquals(
            fields.map { it.signature }.toSortedSet().toList(), listOf(
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String s>",
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String SubField1>"
            ).toSortedSet().toList()
        )
        sig = "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String s>"
        fields = MethodFinder.checkAndParseFieldSignature(sig)
        assertEquals(
            fields.map { it.signature }.toSortedSet().toList(), listOf(
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String s>"
            ).toSortedSet().toList()
        )
        sig = "<net.bytedance.security.app.preprocess.testdata.Sub: * s>"
        fields = MethodFinder.checkAndParseFieldSignature(sig)
        assertEquals(
            fields.map { it.signature }.toSortedSet().toList(), listOf(
                "<net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String s>"
            ).toSortedSet().toList()
        )
    }
}
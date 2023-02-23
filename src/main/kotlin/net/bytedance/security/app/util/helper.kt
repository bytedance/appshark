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


@file:Suppress("unused")

package net.bytedance.security.app.util

import net.bytedance.security.app.Log
import net.bytedance.security.app.Log.logErr
import net.bytedance.security.app.web.DefaultVulnerabilitySaver
import java.util.*
import kotlin.system.exitProcess

/**
 * soot method signature parser
 */
class FunctionSignature(
    var className: String,
    var returnType: String,
    var functionName: String,
    var args: MutableList<String>,
)

fun FunctionSignature.subSignature(): String {
    var s = "${this.returnType} ${this.functionName}("
    s += args.joinToString(separator = ",") + ")"
    return s
}

private enum class MethodSignatureParseState {
    Class, ReturnType, Argument, FunctionName
}


/**
 * @param methodSig for example: <net.bytedance.security.app.bvaa.ComponentRisk.IntentBridge: void IntentBridge2()>
 *     @return FunctionSignature
 */
fun newFunctionSignature(methodSig: String): FunctionSignature {
    if (!(methodSig.startsWith("<") && methodSig.endsWith(">") && methodSig.contains(": "))) {
        Log.logFatal("Format Error $methodSig")
    }
    var s = ""
    val fd = FunctionSignature("", "", "", ArrayList())
    var state = MethodSignatureParseState.Class
    // "<net.bytedance.security.app.bvaa.ComponentRisk.IntentBridge: void IntentBridge2(java.lang.Int,java.lang.String)>
    for (i in 1 until methodSig.length - 1) {
        when (val c = methodSig[i]) {
            ':' -> if (state != MethodSignatureParseState.Class) {
                exitProcess(-2)
            } else {
                // state = ParseState.Space
            }

            ' ' -> {
                when (state) {
                    MethodSignatureParseState.Class -> {
                        fd.className = s
                        state = MethodSignatureParseState.ReturnType
                        s = ""
                    }

                    MethodSignatureParseState.ReturnType -> {
                        fd.returnType = s
                        s = ""
                        state = MethodSignatureParseState.FunctionName
                    }

                    else -> exitProcess(-7)
                }
            }

            ',' -> {
                when (state) {
                    MethodSignatureParseState.Argument -> {
                        fd.args.add(s)
                        s = ""
                    }

                    else -> exitProcess(-8)
                }
            }

            '(' -> {
                when (state) {
                    MethodSignatureParseState.FunctionName -> {
                        fd.functionName = s
                        s = ""
                        state = MethodSignatureParseState.Argument
                    }

                    else -> exitProcess(-9)
                }
            }

            ')' -> {
                when (state) {
                    MethodSignatureParseState.Argument -> {
                        fd.args.add(s)
                        s = ""
                    }

                    else -> exitProcess(-10)
                }
            }

            else -> s += c
        }
    }

    return fd
}

class FieldSignature(
    var className: String,
    var fieldType: String,
    var fieldName: String,
)

fun newFieldSignature(fieldSig: String): FieldSignature {
    if (!(fieldSig.startsWith("<") && fieldSig.endsWith(">") && fieldSig.contains(": "))) {
        Log.logFatal("Format Error $fieldSig")
    }
    val ss = fieldSig.split(" ")
    if (ss.size != 3) {
        Log.logFatal("Format Error $fieldSig")
    }
    return FieldSignature(ss[0].substring(1, ss[0].length - 1), ss[1], ss[2].substring(0, ss[2].length - 1))
}

/**
 * retrieves a function signature from a string, returning the string itself if none is found
 * @param s for example: ref=<net.bytedance.security.app.preprocess.testdata.NotExist: void <init>()>,
 * @return for example: <net.bytedance.security.app.preprocess.testdata.NotExist: void <init>()>
 */
fun getMethodSigFromStr(s: String): String {
    if (s.contains("<") && s.contains(">")) {
        val start = s.indexOf('<')
        val end = s.lastIndexOf('>')
        if (start < end) {
            return s.substring(start, end + 1)
        }
    }
    return s
}

suspend fun uploadJsonResult(outHtmlName: String, jsonBuf: String) {
    val tosUrl = DefaultVulnerabilitySaver.getVulnerabilitySaver()
        .saveVulnerability(jsonBuf.toByteArray(Charsets.UTF_8), outHtmlName)
    logErr("Write All Vulnerabilities to $tosUrl")
}

fun <K, V> Map<K, V>.toSortedMap(): SortedMap<K, V> {
    return this.toSortedMap(compareBy { it.toString() })
}

fun <T> Set<T>.toSortedSet(): SortedSet<T> {
    return this.toSortedSet(compareBy { it.toString() })
}

fun <T> SortedSet<T>.toFormatedString(): String {
    var s = ""
    for (k in this) {
        s += "$k\n"
    }
    return s
}

fun <K, V> SortedMap<K, V>.toFormatedString(): String {
    var s = ""
    for ((k, v) in this) {
        s += "$k=$v\n"
    }
    return s
}

/**
 * String is a string like p0,p1,p2,...
 * @return 0,1,2
 */
fun String.argIndex(): Int {
    return replace("p", "").toInt()
}

/**
 *is this string a valid jimple function signature
 * for example:  <net.bytedance.security.app.preprocess.testdata.NotExist: void <init>()>
 */
fun String.isMethodSignature(): Boolean {
    return this.startsWith("<") && this.endsWith(">") && this.contains("(")
}

/**
 * is this string a valid field signature
 * for example: <net.bytedance.security.app.preprocess.testdata.Sub: java.lang.String SubField1>
 */
fun String.isFieldSignature(): Boolean {
    return this.startsWith("<") && this.endsWith(">") && !this.contains("(")
}
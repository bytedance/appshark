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


package net.bytedance.security.app.ui

import net.bytedance.security.app.Log
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.engineconfig.isLibraryClass
import net.bytedance.security.app.util.JavaAST
import soot.Scene
import soot.SootMethod
import soot.options.Options
import java.io.*
import java.nio.charset.StandardCharsets
import java.nio.file.Files

/**
return method's full Java source code,
 */
internal fun getJavaSource(method: SootMethod): String? {
    val methodSig = method.signature
//    val anonymousMethodSig: String? = null
//    val declaringClassName = method.declaringClass.name
//    if (declaringClassName.contains("$")) {
////        val sootMethodSetMap = ctx.findInstantCallSite(declaringClassName)
////        if (sootMethodSetMap.size == 1) {
////            anonymousMethodSig =
////                methodSig.substring(0, methodSig.indexOf('$')) + methodSig.substring(methodSig.indexOf(':'))
////            methodSig = ctx.findInstantCallSite(sm.declaringClass.name).iterator().next().method.signature
////        } else {
////            methodSig = methodSig.substring(0, methodSig.indexOf('$')) + methodSig.substring(methodSig.indexOf(':'))
////        }
//    }
    genJavaSourceCache(methodSig)
    val methodBody = JavaAST.ASTMap[methodSig] ?: return null
//    var anonymousMethodBody = ""
//    if (anonymousMethodSig != null) {
//        genJavaSourceCache(anonymousMethodSig)
//        anonymousMethodBody = JavaAST.ASTMap[anonymousMethodSig] ?: ""
//    }
    return formatJavaCode(methodBody)
}

fun formatJavaCode(methodBody: String): String {
    val br = BufferedReader(
        InputStreamReader(
            ByteArrayInputStream(
                (methodBody).toByteArray(
                    StandardCharsets.UTF_8
                )
            ),
            StandardCharsets.UTF_8
        )
    )
    val out = StringBuilder()
    var line: String
    var space = 0
    try {
        while (true) {
            line = br.readLine() ?: break
            out.append("  ")
            if (line.endsWith("}")) {
                space = line.length - 1
                out.append(line)
                out.append("\n")
            } else if (line.startsWith(" catch")) {
                for (i in 0 until space) {
                    out.append(" ")
                }
                out.append(line)
                out.append("\n")
            } else if (line.startsWith(" else")) {
                for (i in 0 until space) {
                    out.append(" ")
                }
                val newline = if (line.contains("if (")) {
                    val regex = Regex("if \\(")
                    val arr = line.split(regex).toTypedArray()
                    " else if(${arr[1]}"
                } else {
                    line
                }
                out.append(newline)
            } else {
                out.append(line)
                out.append("\n")
            }
        }
    } catch (e: IOException) {
        e.printStackTrace()
    }
    return out.toString()
}

private fun genJavaSourceCache(methodSig: String) {
    val sootMethod = Scene.v().grabMethod(methodSig) ?: return
    val sc = sootMethod.declaringClass
    try {
        if (isLibraryClass(sc.name)) {
            return
        }
        val javaSource = loadClass(sc.name)
        if (javaSource != null) {
            JavaAST.parseJavaSource(sc.name, javaSource)
        }
    } catch (e: Throwable) {
        e.printStackTrace()
        Log.logErr("ERROR java source load " + sc.name)
    }
}

/**
 * Loads the source code for the specified class
 */
private fun loadClass(className: String): String? {
    val javaSrcPath =
        Options.v().output_dir() + PLUtils.JAVA_SRC + "app/src/main/java/" + className.replace(".", "/") + ".java"
    val javaFile = File(javaSrcPath)
    if (!javaFile.exists()) {
//        PLLog.logErr("ERROR java file not exist $javaSrcPath")
        return null
    }
    try {
        return String(Files.readAllBytes(javaFile.toPath()))
    } catch (e: Exception) {
        Log.logErr("ERROR java file read error $javaSrcPath")
    }
    return null
}

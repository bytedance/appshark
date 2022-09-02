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

import org.eclipse.jdt.core.dom.*
import java.util.concurrent.ConcurrentHashMap

/**
 * generate java source for method
 */
object JavaAST {
    /**
     * key is a method, value is this method's source code
     */
    var ASTMap: MutableMap<String, String> = ConcurrentHashMap()

    private fun createMethodSig(className: String, node: MethodDeclaration) {
        val nameArr = className.split("\\.".toRegex()).toTypedArray()
        val lastName = nameArr[nameArr.size - 1]
        var signature = "<" + className.replace("$", ".") + ": "
        signature += if (node.returnType2 == null) {
            "void "
        } else {
            node.returnType2.toString() + " "
        }
        var isInit = false
        var signatureInit = signature
        if (lastName == node.name.toString()) {
            signatureInit += "<init>"
            isInit = true
        } else {
            signatureInit += node.name
        }
        signature += node.name
        signature += "("
        signatureInit += "("
        if (node.parameters().size > 0) {
            var i = 0
            while (i < node.parameters().size - 1) {
                val param = node.parameters()[i] as SingleVariableDeclaration
                signature += param.type.toString().replace("$", ".") + ","
                signatureInit += param.type.toString().replace("$", ".") + ","
                i++
            }
            val param = node.parameters()[i] as SingleVariableDeclaration
            signature += param.type.toString().replace("$", ".")
            signatureInit += param.type.toString().replace("$", ".")
        }
        signature += ")"
        signatureInit += ")"
        signature += ">"
        signatureInit += ">"
        ASTMap[signature] = node.toString()
        if (isInit) {
            ASTMap[signatureInit] = node.toString()
        }
    }

    fun parseJavaSource(javaSource: String) {
        val parser = ASTParser.newParser(AST.JLS15)
        parser.setSource(javaSource.toCharArray())
        parser.setKind(ASTParser.K_COMPILATION_UNIT)
        parser.createAST(null) as CompilationUnit
    }

    fun parseJavaSource(className: String, javaSource: String) {
        val parser = ASTParser.newParser(AST.JLS15)
        parser.setSource(javaSource.toCharArray())
        parser.setKind(ASTParser.K_COMPILATION_UNIT)
        val cu = parser.createAST(null) as CompilationUnit
        cu.accept(object : ASTVisitor() {
            override fun visit(node: MethodDeclaration): Boolean {
                createMethodSig(className, node)
                return true
            }
        })
    }
}

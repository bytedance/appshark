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

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonPrimitive
import net.bytedance.security.app.MethodFinder
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.SinkBody
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.preprocess.CallSite
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.rules.TaintPosition
import soot.SootMethod
import soot.Value
import soot.jimple.*
import soot.jimple.internal.JimpleLocal

class TaintCheckSanitizerParser(
    private val ctx: PreAnalyzeContext,
    private val sinkBody: SinkBody,
    private val methodSig: String,
    private val rule: TaintFlowRule,
) {

    /**
     *
    "<java.lang.String: boolean contains(java.lang.CharSequence)>": {
    "TaintCheck": ["@this"],
    "NotTaint":["p1"],
    "p0":["..*"]
    }
    TaintCheck,NotTaint, and p0 are and relations,
    multiple sanitizers are created here because they are for the same callsite.
     */
    fun createMethodSanitizer(): ISanitizer {
        val targetMethodSet = MethodFinder.checkAndParseMethodSig(methodSig)
        val callsites = HashSet<CallSite>()
        for (m in targetMethodSet) {
            val callsites2 = ctx.findInvokeCallSite(m)
            callsites.addAll(callsites2)
        }
        if (sinkBody.isEmpty()) {
            return MethodCheckSanitizer(targetMethodSet.toList())
        }
        val possibleMatches: MutableList<TaintCheckSanitizer> = ArrayList()
        for (callsite in callsites) {
            val stmt = callsite.stmt
            val callerMethod = callsite.method
            val invokeExpr = stmt.invokeExpr
            val taintPtrSet = HashSet<PLLocalPointer>()
            val notTaintParamCheckSet = HashSet<PLLocalPointer>()
            val taintArray = sinkBody.TaintCheck
            val taintCheckPtrSet = calcSanitizePtrSet(taintArray, invokeExpr, callerMethod)
            if (taintCheckPtrSet.isNotEmpty()) {
                taintPtrSet.addAll(taintCheckPtrSet)
            } else {
                //we expect this arg must be tainted,but it's empty, it means that it must not be tainted.
                continue
            }
            val cleanArray = sinkBody.NotTaint
            val cleanCheckPtrSet = calcSanitizePtrSet(cleanArray, invokeExpr, callerMethod)
            if (cleanCheckPtrSet.isNotEmpty()) {
                notTaintParamCheckSet.addAll(cleanCheckPtrSet)
            }
            val constStrings: MutableMap<PLLocalPointer, List<String>> = HashMap()

            val isPossibleMatch = calcCheckConstStrToVariable(sinkBody, invokeExpr, callerMethod, constStrings)
            if (!isPossibleMatch) {
                continue
            }

            val s = TaintCheckSanitizer(taintPtrSet, notTaintParamCheckSet, constStrings, rule)
            assert(s.checkAllPtrIsInOneMethod())
            possibleMatches.add(s)
        }
        /// The relationship between different call sites is or, as long as one of them is satisfied, it is ok
        return SanitizeOrRules(possibleMatches)
    }

    /**
     * find target variables for TaintCheck or NotTaint
     * @param taintCheckArray like "TaintCheck": ["p*","@this"]
     * or  "NotTaint": ["p0", "p1"]
     *
     * @param invokeExpr  for example :
     * `virtualinvoke r1.<java.lang.String: boolean contains(java.lang.CharSequence)>("..")`
     * @param callerMethod the method that contains the invokeExpr
     * @return   variables need to be checked
     */
    private fun calcSanitizePtrSet(
        taintCheckArray: List<String>?,
        invokeExpr: InvokeExpr,
        callerMethod: SootMethod
    ): Set<PLLocalPointer> {
        val ptrSet: MutableSet<PLLocalPointer> = HashSet()
        if (taintCheckArray == null) {
            return ptrSet
        }
        for (taintParam in taintCheckArray) {
            val taintPosition = TaintPosition(taintParam)
            if (taintPosition.position == TaintPosition.This) {
                if (invokeExpr is InstanceInvokeExpr) {
                    val base = invokeExpr.base as JimpleLocal
                    val ptr = PLLocalPointer(
                        callerMethod,
                        base.name, base.type
                    )
                    ptrSet.add(ptr)
                }
            } else if (taintPosition.position == TaintPosition.AllArgument) {
                for (arg in invokeExpr.args) {
                    if (arg is JimpleLocal) {
                        val ptr = PLLocalPointer(
                            callerMethod,
                            arg.name, arg.getType()
                        )
                        ptrSet.add(ptr)
                    }
                }
            } else if (taintPosition.isConcreteArgument()) {
                val i = taintPosition.position
                if (i < invokeExpr.argCount) {
                    val arg = invokeExpr.getArg(i)
                    if (arg is JimpleLocal) {
                        val ptr = PLLocalPointer(
                            callerMethod,
                            arg.name, arg.getType()
                        )
                        ptrSet.add(ptr)
                    }
                }
            }
        }
        return ptrSet
    }

    /**
     * @param sinkBody
     * "<java.lang.String: boolean contains(java.lang.CharSequence)>": {
     * "TaintCheck": ["@this"],
     * "p0":["..*"]
     * "p*":["..*"]
     * }
     * @param invokeExpr The expression that calls this function, for example: r1.contains(r3)
     * @param callerMethod the method that contains the invokeExpr
     * @param constStrings result if found,for example key is r3, and value is "..*"
     * @return true if it is possible to match the sanitizer, false otherwise.
     */
    private fun calcCheckConstStrToVariable(
        sinkBody: SinkBody,
        invokeExpr: InvokeExpr,
        callerMethod: SootMethod,
        constStrings: MutableMap<PLLocalPointer, List<String>>
    ): Boolean {
        if (sinkBody.pstar != null) {
            for (arg in invokeExpr.args) {
                if (!calcForOneArg(callerMethod, sinkBody.pstar, arg, constStrings)) {
                    return false
                }
            }
        } else {
            sinkBody.pmap?.forEach {
                val index = it.key.slice(1 until it.key.length).toInt()
                if (index < invokeExpr.argCount) {
                    val arg = invokeExpr.getArg(index)
                    if (!calcForOneArg(callerMethod, it.value, arg, constStrings)) {
                        return false
                    }
                }
            }
        }
        return true
    }

    private fun calcForOneArg(
        callerMethod: SootMethod,
        constStrArray: List<JsonElement>,
        arg: Value,
        constStrings: MutableMap<PLLocalPointer, List<String>>
    ): Boolean {
        val patterns = constStrArray.map { it.jsonPrimitive.content }
        if (arg is Constant) {
            var possible = false
            for (pattern in patterns) {
                if (TaintCheckSanitizer.isSanitizeStrMatch(pattern, arg.getStringValue())) {
                    possible = true
                    break
                }
            }
            if (!possible) {
                return false // this call site cannot match sanitizer
            }

        } else if (arg is JimpleLocal) {
            val ptr = PLLocalPointer(callerMethod, arg.name, arg.type)
            constStrings[ptr] = patterns
        }
        return true
    }
}

/**
 *
 * If it is a string, return itself
 * numeric constant, return its string
 * null, return "null"
 */
fun Constant.getStringValue(): String {
    when (this) {
        is StringConstant -> {
            return value
        }

        is IntConstant -> {
            return value.toString()
        }

        is NullConstant -> {
            return "null"
        }

        is LongConstant -> {
            return value.toString()
        }

        else -> {
//        throw IllegalArgumentException("unsupported constant type: ${this.javaClass.name}")
        }
    }
    return this.toString()
}

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


package net.bytedance.security.app.ruleprocessor

import net.bytedance.security.app.MethodFinder
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.SinkBody
import net.bytedance.security.app.preprocess.CallSite
import net.bytedance.security.app.result.OutputSecResults
import net.bytedance.security.app.rules.ConstNumberModeRule
import net.bytedance.security.app.rules.ConstStringModeRule
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.rules.TaintPosition
import net.bytedance.security.app.taintflow.TaintAnalyzer
import net.bytedance.security.app.ui.ConstExtractModeHtmlWriter
import soot.SootMethod
import soot.Value
import soot.jimple.*
import soot.jimple.internal.JReturnStmt
import soot.jimple.internal.JimpleLocal

abstract class ConstModeProcessor(ctx: PreAnalyzeContext) : TaintFlowRuleProcessor(ctx) {
    suspend fun calcConstValueEntries(
        rule: TaintFlowRule,
        sink: Map<String, SinkBody>,
        analyzers: MutableList<TaintAnalyzer>
    ) {

        for ((methodSigRule, sinkContentObj) in sink) {
            val sinkMethodSet = MethodFinder.checkAndParseMethodSig(methodSigRule)
            if (sinkContentObj.TaintCheck == null) {
                throw Exception("${rule.name} sink TaintCheck is null")
            }

            val taintArr = sinkContentObj.TaintCheck
            val taintParamTypeArr = sinkContentObj.TaintParamType
            for (sinkMethod in sinkMethodSet) {
                if (sinkContentObj.LibraryOnly == true && ctx.callGraph.isUserCode(sinkMethod)) {
                    continue
                }

                val callSites = ctx.findInvokeCallSite(sinkMethod)
                calcConstValFlowEntries(rule, callSites, taintArr, taintParamTypeArr, analyzers)
                /*
                If the sink point is  return, the sink point should be a variable or constant at the position of the return.
                 */
                if (TaintRuleSourceSinkCollector.hasReturn(taintArr)) {
                    if (!sinkMethod.hasActiveBody()) {
                        continue
                    }
                    calcReturnSink(rule, sinkMethod, analyzers)
                }
            }
        }
    }

    private suspend fun calcReturnSink(
        rule: TaintFlowRule,
        sinkMethod: SootMethod,
        analyzers: MutableList<TaintAnalyzer>
    ) {
        val analyzer = TaintAnalyzer(rule, sinkMethod)
        for (stmt in sinkMethod.activeBody.units) {
            if (stmt !is JReturnStmt) {
                continue
            }
            val retOp = stmt.op
            calcConstPtr(rule, retOp, sinkMethod, stmt, analyzer)
        }
        if (analyzer.data.pointerIndexMap.isNotEmpty()) {
            analyzers.add(analyzer)
        }
    }

    private suspend fun calcConstValFlowEntries(
        rule: TaintFlowRule,
        entry: Set<CallSite>,
        paramArr: List<String>?,
        taintParamTypeArr: List<String>?,
        analyzers: MutableList<TaintAnalyzer>
    ) {

        entry.forEach {
            val callerMethod = it.method
            val callerStmtSet = it.stmt
            val entrySet: MutableSet<SootMethod> = HashSet()
            ctx.callGraph.queryTopEntry(false, callerMethod, rule.traceDepth, entrySet)
            if (entrySet.size > 1) {
                entrySet.remove(callerMethod)
            }
            for (method in entrySet) {
                val analyzer = TaintAnalyzer(rule, method)
                calcAllConstPointers(rule, paramArr, taintParamTypeArr, callerMethod, setOf(callerStmtSet), analyzer)
                if (analyzer.data.pointerIndexMap.isNotEmpty()) {
                    analyzers.add(analyzer)
                }
            }
        }
    }


    private suspend fun calcAllConstPointers(
        rule: TaintFlowRule,
        paramArr: List<String>?,
        taintParamTypeArr: List<String>?,
        callerMethod: SootMethod,
        callerStmtSet: Set<Stmt>,
        analyzer: TaintAnalyzer
    ) {
        for (callerStmt in callerStmtSet) {
            val invokeExpr = callerStmt.invokeExpr
            if (paramArr != null) {
                for (param in paramArr) {
                    val taintPosition = TaintPosition(param)
                    if (taintPosition.position == TaintPosition.AllArgument) {
                        for (arg in invokeExpr.args) {
                            if (!TaintRuleSourceSinkCollector.isValidType(taintParamTypeArr, arg.type)) {
                                continue
                            }
                            calcConstPtr(rule, arg, callerMethod, callerStmt, analyzer)
                        }
                    } else if (taintPosition.isConcreteArgument()) {
                        val index = taintPosition.position
                        if (index < invokeExpr.argCount) {
                            val arg = invokeExpr.getArg(index)
                            if (!TaintRuleSourceSinkCollector.isValidType(taintParamTypeArr, arg.type)) {
                                continue
                            }
                            calcConstPtr(rule, arg, callerMethod, callerStmt, analyzer)
                        }
                    }
                }
            }
        }
    }


    private suspend fun calcConstPtr(
        rule: TaintFlowRule,
        arg: Value?,
        callerMethod: SootMethod,
        callerStmt: Stmt,
        analyzer: TaintAnalyzer
    ) {
        if (arg is JimpleLocal) {
            analyzer.data.allocPtrWithStmt(callerStmt, callerMethod, arg.name, arg.type, false)
        } else if (arg is StringConstant && rule is ConstStringModeRule) {
            constStrArgMatch(rule, callerMethod, callerStmt, arg.value)
        } else if (arg is NumericConstant && rule is ConstNumberModeRule) {
            constNumArgMatch(rule, callerMethod, callerStmt, arg)
        }
    }


    suspend fun constStrArgMatch(
        rule: ConstStringModeRule,
        callerMethod: SootMethod,
        callerStmt: Stmt,
        constStr: String
    ): Boolean {
        var isMatch = false
        if (rule.hasConstLen) {
            val constStrLen = constStr.length
            if (constStrLen > 0 && rule.constLen != null && constStrLen % rule.constLen == 0) {

                if (rule.targetStringArr != null) {
                    if (isMatchTargetConstStr(constStr, rule.targetStringArr)) {
                        isMatch = true
                    }
                } else {
                    isMatch = true
                }
            }
        } else {
            if (rule.targetStringArr != null) {
                if (isMatchTargetConstStr(constStr, rule.targetStringArr)) {
                    isMatch = true
                }
            } else if (rule.minLen != null) {
                if (constStr.length >= rule.minLen) {
                    isMatch = true
                }
            } else {
                isMatch = true
            }
        }
        if (isMatch) {
            ConstExtractModeHtmlWriter(
                OutputSecResults,
                rule,
                callerMethod,
                callerStmt,
                constStr
            ).addVulnerabilityAndSaveResultToOutput()
        }
        return isMatch
    }


    suspend fun constNumArgMatch(
        rule: ConstNumberModeRule,
        callerMethod: SootMethod,
        callerStmt: Stmt,
        arg: NumericConstant
    ): Boolean {
        if (arg is IntConstant) {
            return constNumArgMatch(rule, callerMethod, callerStmt, arg.value.toLong())
        } else if (arg is LongConstant) {
            return constNumArgMatch(rule, callerMethod, callerStmt, arg.value)
        }
        return false
    }


    suspend fun constNumArgMatch(
        rule: ConstNumberModeRule,
        callerMethod: SootMethod,
        callerStmt: Stmt,
        num: Long
    ): Boolean {
        if (rule.targetNumberArr != null) {
            if (rule.targetNumberArr.contains(num.toInt())) {
                ConstExtractModeHtmlWriter(
                    OutputSecResults,
                    rule,
                    callerMethod,
                    callerStmt,
                    num.toString()
                ).addVulnerabilityAndSaveResultToOutput()
                return true
            }
        } else {
            ConstExtractModeHtmlWriter(
                OutputSecResults,
                rule,
                callerMethod,
                callerStmt,
                num.toString()
            ).addVulnerabilityAndSaveResultToOutput()
            return true
        }
        return false
    }

    companion object {

        fun isMatchTargetConstStr(targetStr: String, targetStrArr: List<String>): Boolean {
            for (str in targetStrArr) {
                if (PLUtils.isStrMatch(str, targetStr))
                    return true
            }
            return false
        }
    }
}
package net.bytedance.security.app.sanitizer.v2

import net.bytedance.security.app.MethodFinder
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.preprocess.CallSite
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.rules.TaintPosition
import net.bytedance.security.app.sanitizer.*
import soot.SootMethod
import soot.Value
import soot.jimple.*
import soot.jimple.internal.JimpleLocal

class TaintCheckSanitizerParserV2(
    private val check: SanitizerCheckItem,
    private val methodSignature: String,
    private val ctx: PreAnalyzeContext,
    private val rule: TaintFlowRule
) {
    fun createMethodSanitizer(): ISanitizer {
        val targetMethodSet = MethodFinder.checkAndParseMethodSig(methodSignature)
        val callsites = HashSet<CallSite>()
        for (m in targetMethodSet) {
            val callsites2 = ctx.findInvokeCallSite(m)
            callsites.addAll(callsites2)
        }
        //如果只是定义了一个method，表示只要调用了就算通过，保持兼容性
        if (check.subCheckContent.isEmpty()) {
            return MethodCheckSanitizer(targetMethodSet.toList())
        }
        val resultOrSanitizers = ArrayList<ISanitizer>()
        for (callsite in callsites) {
            val stmt = callsite.stmt
            val callerMethod = callsite.method
            val invokeExpr = stmt.invokeExpr
            //每一个callsite都要执行一遍check的创建
            val sanitizerLevel1 = ArrayList<ISanitizer>()
            check.subCheckContent.forEach { subCheckContent ->
                val sanitizerLevel2 = ArrayList<ISanitizer>()

                subCheckContent.position.forEach { position ->
                    //两种情况，check是否taint
                    if (subCheckContent.positionCheckType == SANITIZER_POSITION_CHECK_TYPE_SOURCE
                        || subCheckContent.positionCheckType == SANITIZER_POSITION_CHECK_TYPE_SINK
                    ) {
                        val taintCheckPtrSet = calcSanitizePtrSet(position, stmt, callerMethod)
                        //如果找不到调用点，说明不满足taint check条件
                        if (taintCheckPtrSet.isEmpty()) {
                            sanitizerLevel2.add(MustNotPassSanitizer())
                        } else {
                            sanitizerLevel2.add(
                                VariableTaintCheckSanitizer(
                                    subCheckContent.positionCheckType,
                                    taintCheckPtrSet.toList(),
                                    rule
                                )
                            )
                        }
                    } else if (subCheckContent.positionCheckType == SANITIZER_POSITION_CHECK_TYPE_CONST_VALUE) {
                        val constValueCheckSanitizer = calcCheckConstStrToVariable(
                            position,
                            invokeExpr,
                            callerMethod,
                            subCheckContent.argumentValue!!
                        )
                        sanitizerLevel2.add(constValueCheckSanitizer)
                    } else {
                        throw IllegalArgumentException("unsupported positionCheckType ${subCheckContent.positionCheckType}")
                    }
                }
                sanitizerLevel1.add(
                    SanitizerFactoryV2.createRulesWithRelation(
                        subCheckContent.relation,
                        sanitizerLevel2
                    )
                )
            }
            resultOrSanitizers.add(
                SanitizerFactoryV2.createRulesWithRelation(
                    check.subCheckContentRelation,
                    sanitizerLevel1
                )
            )
        }
        var relation = SANITIZER_RELATION_ANY
        if (check.instanceRelation != null && check.instanceRelation!!.isNotEmpty()) {
            relation = check.instanceRelation!!
        }
        return SanitizerFactoryV2.createRulesWithRelation(relation, resultOrSanitizers)
    }

    /**
     * 应用在函数调用检查的场合，根据position来收集stmt中对应的变量
     * @param position 比如p0,p1,p*,@this,ret等
     * @param stmt  for example :
     * `r3=virtualinvoke r1.<java.lang.String: boolean contains(java.lang.CharSequence)>("..")`
     * @param callerMethod the method that contains the invokeExpr
     * @return  在stmt中涉及到的变量
     */
    private fun calcSanitizePtrSet(
        position: String,
        stmt: Stmt,
        callerMethod: SootMethod
    ): Set<PLLocalPointer> {
        val ptrSet: MutableSet<PLLocalPointer> = HashSet()
        val invokeExpr = stmt.invokeExpr
        val taintPosition = TaintPosition(position)
        if (taintPosition.position == TaintPosition.This) {
            if (invokeExpr is InstanceInvokeExpr) {
                val base = invokeExpr.base as JimpleLocal
                val ptr = PLLocalPointer(
                    callerMethod,
                    base.name, base.type
                )
                ptrSet.add(ptr)
            }
        } else if (taintPosition.position == TaintPosition.Return) {
            //return 只出现在一种场景，就是从return流向sink
            if (stmt is AssignStmt) {
                val left = stmt.leftOp
                if (left is JimpleLocal) {
                    val ptr = PLLocalPointer(callerMethod, left.name, left.type)
                    ptrSet.add(ptr)
                }

            }
        } else if (taintPosition.position == TaintPosition.AllArgument) {
            for (arg in invokeExpr.args) {
                if (arg is JimpleLocal) {
                    val ptr = PLLocalPointer(
                        callerMethod,
                        arg.name, arg.type
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
        return ptrSet
    }

    /**
     * 计算argValues的常量字符串传递给position的场景，
     * @param position 值为p0,p1,p*，不能是this，ret
     * @param invokeExpr The expression that calls this function, for example: r1.contains(r3)
     * @param callerMethod the method that contains the invokeExpr
     * @param sanitizers  创建的sanitizer
     * @return true if it is possible to match the sanitizer, false otherwise.
     */
    private fun calcCheckConstStrToVariable(
        position: String,
        invokeExpr: InvokeExpr,
        callerMethod: SootMethod,
        argValues: List<String>
    ): ISanitizer {
        if (position == "p*") {
            val sanitizers = ArrayList<ISanitizer>()
            for (arg in invokeExpr.args) {
                sanitizers.add(calcForOneArg(callerMethod, argValues, arg))
            }
            if (sanitizers.isEmpty()) {
                return MustNotPassSanitizer()
            }
            //对于p*来说，只要任意一个参数满足要求就ok，这是强制内置的含义
            return SanitizeOrRules(sanitizers)
        } else {
            val index = position.slice(1 until position.length).toInt()
            if (index < invokeExpr.argCount) {
                val arg = invokeExpr.getArg(index)
                return calcForOneArg(callerMethod, argValues, arg)
            }
            return MustNotPassSanitizer()
        }
    }

    private fun calcForOneArg(
        callerMethod: SootMethod,
        argValues: List<String>,
        arg: Value,
    ): ISanitizer {
        if (arg is Constant) {
            var possible = false
            for (pattern in argValues) {
                if (TaintCheckSanitizer.isSanitizeStrMatch(pattern, arg.getStringValue())) {
                    possible = true
                    break
                }
            }
            //如果常量匹配到了，后续的match就一定为真
            if (!possible) {
                return MustNotPassSanitizer()
            } else {
                return MustPassSanitizer()
            }

        } else if (arg is JimpleLocal) {
            val ptr = PLLocalPointer(callerMethod, arg.name, arg.type)
            return VariableValueCheckSanitizer(ptr, argValues, rule)
        }
        throw IllegalArgumentException("unsupported arg type ${arg.javaClass.name}")
        return MustNotPassSanitizer()
    }
}
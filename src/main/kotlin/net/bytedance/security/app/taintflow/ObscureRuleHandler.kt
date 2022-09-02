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

package net.bytedance.security.app.taintflow

import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.getConfig
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.pointer.PointerFactory
import net.bytedance.security.app.rules.TaintPosition
import soot.UnknownType
import soot.jimple.Stmt

class ObscureRuleHandler(
    val ctx: AnalyzeContext,
    private val pt: PointerFactory,
) {
    /**
     * add relations between pointer by rules in [ruleList]
     * @param stmt the call stmt,for example,r=o.f(a1,a2,a3)
     * @param basePointer o in r=o.f(a1,a2,a3)
     * @param ruleList the rules to add relations
     * @param baseDataPointers o.@data
     * @param receivePointer r in r=o.f(a1,a2,a3)
     * @param argPointers a1,a2,a3 in r=o.f(a1,a2,a3)
     * @param isPointerRule whether the rule is pointer rule or variable flow rule
     */
    fun addEdgeByRule(
        stmt: Stmt,
        ruleList: List<FlowItem>,
        basePointer: PLPointer?,
        baseDataPointers: Set<PLPointer>?,
        receivePointer: PLPointer?,
//        recvDataPtrs: Set<PLPointer>,
        argPointers: List<PLPointer>,
        isPointerRule: Boolean
    ) {
        for (entry in ruleList) {
            val (from, to) = entry
            when (from.position) {
                TaintPosition.This -> when (to.position) {
                    TaintPosition.Return -> baseToReturnEdge(isPointerRule, stmt, basePointer, receivePointer)
//                    Wrapper.RET_DATA -> baseToReturnDataEdge(isPointerRule, stmt, basePtr, recvDataPtrs)
                    TaintPosition.AllArgument -> baseToAllArgEdge(isPointerRule, stmt, basePointer, argPointers)
                    else -> {
                        val index = to.position
                        if (index >= argPointers.size) {
                            break
                        }
                        baseToArgEdge(isPointerRule, stmt, basePointer, argPointers[index])
                    }
                }
                TaintPosition.ThisAllField -> when (to.position) {
                    TaintPosition.Return -> baseDataToReturnEdge(isPointerRule, stmt, baseDataPointers, receivePointer)
//                    Wrapper.RET_DATA -> baseDataToReturnDataEdge(isPointerRule, stmt, baseDataPtrs, recvDataPtrs)
                    TaintPosition.AllArgument -> baseDataToArgEdge(isPointerRule, stmt, baseDataPointers, argPointers)
                    else -> {
                        val index = to.position
                        if (index >= argPointers.size) {
                            break
                        }
                        baseDataToArgEdge(isPointerRule, stmt, baseDataPointers, argPointers[index])
                    }
                }
                TaintPosition.AllArgument -> when (to.position) {
                    TaintPosition.This -> argToBaseEdge(isPointerRule, stmt, argPointers, basePointer)
                    TaintPosition.ThisAllField -> argToBaseDataEdge(isPointerRule, stmt, argPointers, baseDataPointers)
                    TaintPosition.Return -> argToRetEdge(isPointerRule, stmt, argPointers, receivePointer)
//                    Wrapper.RET_DATA -> argToRetDataEdge(isPointerRule, stmt, argPtrs, recvDataPtrs)
                }
                else -> {
                    val fromIndex = from.position
                    if (fromIndex >= argPointers.size) {
                        break
                    }
                    when (to.position) {
                        TaintPosition.This -> argToBaseEdge(isPointerRule, stmt, argPointers[fromIndex], basePointer)
                        TaintPosition.ThisAllField -> argToBaseDataEdge(
                            isPointerRule,
                            stmt,
                            argPointers[fromIndex],
                            baseDataPointers
                        )
                        TaintPosition.Return -> argToRetEdge(
                            isPointerRule,
                            stmt,
                            argPointers[fromIndex],
                            receivePointer
                        )
//                        Wrapper.RET_DATA -> argToRetDataEdge(isPointerRule, stmt, argPtrs[i_index], recvDataPtrs)
                        else -> {
                            // p1 -> p2
                            val toIndex = to.position
                            assert(fromIndex != toIndex)
                            if (toIndex >= argPointers.size) {
                                break
                            }
                            argToArgEdge(isPointerRule, stmt, argPointers[fromIndex], argPointers[toIndex])
                        }
                    }
                }
            }
        }
    }


    /*
     * base.func(arg1, arg2)
     * arg1 -> base.'@data'
     * arg2 -> base.'@data'
     * */
    private fun argToBaseDataEdge(
        isPointerRule: Boolean,
        stmt: Stmt,
        argPtrs: List<PLPointer>,
        baseDataPtrs: Set<PLPointer>?
    ) {
        if (baseDataPtrs == null) {
            return
        }
        for (baseDataPtr in baseDataPtrs) {
            for (argPtr in argPtrs) {
                addEdge(isPointerRule, argPtr, baseDataPtr, stmt)
            }
        }
    }

    private fun argToBaseDataEdge(
        isPointerRule: Boolean,
        stmt: Stmt,
        argPtr: PLPointer,
        baseDataPtrs: Set<PLPointer>?
    ) {
        if (baseDataPtrs == null) {
            return
        }
        for (baseDataPtr in baseDataPtrs) {
            addEdge(isPointerRule, argPtr, baseDataPtr, stmt)
        }
    }

    /*
     * base.func(arg1, arg2)
     * arg1 -> base
     * arg2 -> base
     * */
    private fun argToBaseEdge(isPointerRule: Boolean, stmt: Stmt, argPtrs: List<PLPointer>, basePtr: PLPointer?) {
        if (basePtr == null) {
            return
        }
        for (argPtr in argPtrs) {
            addEdge(isPointerRule, argPtr, basePtr, stmt)
        }
    }

    private fun argToBaseEdge(isPointerRule: Boolean, stmt: Stmt, argPtr: PLPointer, basePtr: PLPointer?) {
        if (basePtr == null) {
            return
        }
        addEdge(isPointerRule, argPtr, basePtr, stmt)
    }

    private fun argToRetEdge(isPointerRule: Boolean, stmt: Stmt, argPtrs: List<PLPointer>, recvPtr: PLPointer?) {
        for (argPtr in argPtrs) {
            addEdge(isPointerRule, argPtr, recvPtr, stmt)
        }
    }

    private fun argToRetEdge(isPointerRule: Boolean, stmt: Stmt, argPtr: PLPointer, recvPtr: PLPointer?) {
        addEdge(isPointerRule, argPtr, recvPtr, stmt)
    }

    private fun argToArgEdge(isPointerRule: Boolean, stmt: Stmt, argPtr1: PLPointer, argPtr2: PLPointer) {
        addEdge(isPointerRule, argPtr1, argPtr2, stmt)
    }

    private fun argDataToArgEdge(isPointerRule: Boolean, stmt: Stmt, argPtr1: PLPointer, argPtr2: PLPointer?) {
        if (!ctx.isInPointToSet(argPtr1)) {
            return
        }
        for (obj1 in ctx.getPointToSet(argPtr1)!!) {
            val argObjPtr1: PLPointer = pt.allocObjectField(obj1, PLUtils.DATA_FIELD, UnknownType.v())
            addEdge(isPointerRule, argObjPtr1, argPtr2, stmt)
        }
    }

    private fun argToArgDataEdge(isPointerRule: Boolean, stmt: Stmt, argPtr1: PLPointer, argPtr2: PLPointer) {
        if (!ctx.isInPointToSet(argPtr2)) {
            return
        }
        for (obj2 in ctx.getPointToSet(argPtr2)!!) {
            val argObjPtr2: PLPointer = pt.allocObjectField(obj2, PLUtils.DATA_FIELD, UnknownType.v())
            addEdge(isPointerRule, argPtr1, argObjPtr2, stmt)
        }
    }

    private fun argDataToArgDataEdge(isPointerRule: Boolean, stmt: Stmt, argPtr1: PLPointer, argPtr2: PLPointer) {
        if (!ctx.isInPointToSet(argPtr1) || !ctx.isInPointToSet(argPtr2)) {
            return
        }
        for (obj1 in ctx.getPointToSet(argPtr1)!!) {
            val argObjPtr1: PLPointer = pt.allocObjectField(obj1, PLUtils.DATA_FIELD, UnknownType.v())
            for (obj2 in ctx.getPointToSet(argPtr2)!!) {
                val argObjPtr2: PLPointer = pt.allocObjectField(obj2, PLUtils.DATA_FIELD, UnknownType.v())
                addEdge(isPointerRule, argObjPtr1, argObjPtr2, stmt)
            }
        }
    }

    private fun argToRetDataEdge(
        isPointerRule: Boolean,
        stmt: Stmt,
        argPtrs: List<PLPointer>,
        recvDataPtrs: Set<PLPointer>
    ) {
        for (argPtr in argPtrs) {
            for (recvDataPtr in recvDataPtrs) {
                addEdge(isPointerRule, argPtr, recvDataPtr, stmt)
            }
        }
    }

    private fun argToRetDataEdge(isPointerRule: Boolean, stmt: Stmt, argPtr: PLPointer, recvDataPtrs: Set<PLPointer>) {
        for (recvDataPtr in recvDataPtrs) {
            addEdge(isPointerRule, argPtr, recvDataPtr, stmt)
        }
    }

    /*
     * ret = base.func(arg1, arg2)
     * base.'@data' -> ret
     * */
    private fun baseDataToReturnEdge(
        isPointerRule: Boolean,
        stmt: Stmt,
        baseDataPtrs: Set<PLPointer>?,
        recvPtr: PLPointer?
    ) {
        if (baseDataPtrs == null) {
            return
        }
        if (recvPtr == null) {
            return
        }
        for (baseDataPtr in baseDataPtrs) {
            addEdge(isPointerRule, baseDataPtr, recvPtr, stmt)
        }
    }

    private fun baseDataToReturnDataEdge(
        isPointerRule: Boolean,
        stmt: Stmt,
        baseDataPtrs: Set<PLPointer>?,
        recvDataPtrs: Set<PLPointer>
    ) {
        if (baseDataPtrs == null) {
            return
        }
        for (baseDataPtr in baseDataPtrs) {
            for (recvDataPtr in recvDataPtrs) {
                addEdge(isPointerRule, baseDataPtr, recvDataPtr, stmt)
            }
        }
    }

    /*
     * ret = base.func(arg1, arg2)
     * base.'@data' -> arg1
     * base.'@data' -> arg2
     * */
    private fun baseDataToArgEdge(
        isPointerRule: Boolean,
        stmt: Stmt,
        baseDataPtrs: Set<PLPointer>?,
        argPtrs: List<PLPointer>
    ) {
        if (baseDataPtrs == null) {
            return
        }
        for (baseDataPtr in baseDataPtrs) {
            for (argPtr in argPtrs) {
                addEdge(isPointerRule, baseDataPtr, argPtr, stmt)
            }
        }
    }

    private fun baseDataToArgEdge(
        isPointerRule: Boolean,
        stmt: Stmt,
        baseDataPtrs: Set<PLPointer>?,
        argPtr: PLPointer
    ) {
        if (baseDataPtrs == null) {
            return
        }
        for (baseDataPtr in baseDataPtrs) {
            addEdge(isPointerRule, baseDataPtr, argPtr, stmt)
        }
    }

    /*
     * ret = base.func(arg1, arg2)
     * base -> arg1
     * base -> arg2
     * */
    private fun baseToAllArgEdge(isPointerRule: Boolean, stmt: Stmt, basePtr: PLPointer?, argPtrs: List<PLPointer>) {
        if (basePtr == null) {
            return
        }
        for (argPtr in argPtrs) {
            addEdge(isPointerRule, basePtr, argPtr, stmt)
        }
    }

    /**
     * ret = base.func(arg1, arg2)
     * base -> arg1
     */
    private fun baseToArgEdge(isPointerRule: Boolean, stmt: Stmt, basePtr: PLPointer?, argPtr: PLPointer) {
        if (basePtr == null) {
            return
        }
        addEdge(isPointerRule, basePtr, argPtr, stmt)
    }

    /*
     * ret = base.func(arg1, arg2)
     * base -> ret
     * */
    private fun baseToReturnEdge(isPointerRule: Boolean, stmt: Stmt, basePtr: PLPointer?, recvPtr: PLPointer?) {
        if (recvPtr == null) {
            return
        }
        if (basePtr == null) {
            return
        }
        addEdge(isPointerRule, basePtr, recvPtr, stmt)
    }

    /**
     * ret = base.func(arg1, arg2)
     *  base-> ret.data
     *  for example:
     *  String s;
     *  char[] chars=s.toCharArray();
     */
    private fun baseToReturnDataEdge(
        isPointerRule: Boolean,
        stmt: Stmt,
        basePtr: PLPointer?,
        recvDataPtrs: Set<PLPointer>
    ) {
        if (basePtr == null) {
            return
        }
        for (recvDataPtr in recvDataPtrs) {
            addEdge(isPointerRule, basePtr, recvDataPtr, stmt)
        }
    }

    private fun addEdge(
        isPointerRule: Boolean,
        srcPtr: PLPointer,
        dstPtr: PLPointer?,
        @Suppress("UNUSED_PARAMETER") stmt: Stmt
    ) {
        if (dstPtr == null) {
            return
        }
        if (isPointerRule) {
            ctx.addPtrEdge(srcPtr, dstPtr, !getConfig().skipPointerPropagationForLibraryMethod)
        } else {
            ctx.addVariableFlowEdge(srcPtr, dstPtr)
        }
    }

}
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


package net.bytedance.security.app.pathfinder

import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.pointer.*
import net.bytedance.security.app.taintflow.AnalyzeContext
import soot.SootMethod
import soot.UnknownType
import soot.Value
import soot.jimple.*
import soot.jimple.internal.JAssignStmt
import soot.jimple.internal.JReturnStmt
import soot.jimple.internal.JimpleLocal

/**
give the source and destination pointer, find the jimple statements
that assign the source pointer to the destination pointer
 */
class TaintFlowEdgeFinder(val ctx: AnalyzeContext) {
    //todo 1. 这里面有一个问题，就是patchMethod的情况，会导致无法关联
    /*
    另外还有一种情况找不到关联的
    obj->{obj1,obj2}
    obj1.f(arg1); taintPath:arg1->obj1
    //在另外一个地方
    obj2.f(arg2); taintPath:arg2->obj2
    在经过指针传播后，会得到arg1->obj2的传播关系，这时候也会找不到关联路径
     */
    /**
     * give the source and destination pointer, find the jimple statements
     * that assign the source pointer to the destination pointer
     * @return for dst=obj.f() ,src is in the method f,and dst is in the caller of method f,
     * so there are two statements connect the src and dst
     */
    fun getPossibleEdge(srcPtr: PLPointer, dstPtr: PLPointer): List<TaintEdge>? {
        if (srcPtr is PLLocalPointer) {
            if (dstPtr is PLLocalPointer) {
                if (dstPtr.isThis) {
                    return localToThis(srcPtr, dstPtr)
                } else if (dstPtr.isParam) {
                    return localToParam(srcPtr, dstPtr)
                } else {
                    return localToLocal(srcPtr, dstPtr)
                }
            } else if (dstPtr is PLPtrStaticField) {
                return localToField(srcPtr, dstPtr)
            } else { // PLPtrObjectField
                return localToObjField(srcPtr, dstPtr as PLPtrObjectField)
            }
        } else if (srcPtr is PLPtrStaticField) {
            return fieldToLocal(srcPtr, dstPtr as PLLocalPointer)
        } else { // PLPtrObjectField
            return fieldToLocal(srcPtr, dstPtr as PLLocalPointer)
        }
    }

    /*
     * obj.f(arg1)
     * flow from arg1 to obj
      *
     * */
    private fun localToThis(localPtr: PLLocalPointer, thisPtr: PLLocalPointer): List<TaintEdge>? {
        val edges = ArrayList<TaintEdge>()
        //they must be in the same method
        assert(localPtr.method != thisPtr.method)
        for (unit in localPtr.method.activeBody.units) {
            val stmt = unit as Stmt
            if (!stmt.containsInvokeExpr()) {
                continue
            }
            if (stmt.invokeExpr.method != thisPtr.method) {
                continue
            }
            for (valueBox in stmt.useAndDefBoxes) {
                val v = valueBox.value
                if (v !is JimpleLocal || v.name != localPtr.variable) {
                    continue
                }
                edges.add(TaintEdge(localPtr.method, stmt))
            }
        }
        if (edges.isEmpty()) {
            return localToThisFindInCacheStmts(localPtr.method, localPtr, thisPtr)
        }
        return edges
    }

    //尝试在
    private fun localToThisFindInCacheStmts(
        method: SootMethod,
        localPtr: PLLocalPointer,
        thisPtr: PLLocalPointer
    ): List<TaintEdge>? {
        val dstStmtSet = HashSet(ctx.LPtrToStmts.get(thisPtr))
        if (dstStmtSet.isEmpty()) {
            return null
        }
        val srcStmts = ctx.RPtrToStmts.get(localPtr) ?: setOf()
        dstStmtSet.retainAll(ctx.RPtrToStmts.get(localPtr)!!)
        for (unit in method.activeBody.units) {
            if (unit !is Stmt) {
                continue
            }
            val stmt = unit as Stmt
            if (dstStmtSet.contains(stmt)) {
                val edges = ArrayList<TaintEdge>()
                edges.add(TaintEdge(localPtr.method, stmt))
                return edges
            }
        }
        return null
    }

    /**
     *
     * obj.f(r1)
     * flow from r1 to @parameter0
     */
    private fun localToParam(srcPtr: PLLocalPointer, dstPtr: PLLocalPointer): List<TaintEdge>? {
        val edges = ArrayList<TaintEdge>()
        assert(dstPtr.isParam)
        for (unit in srcPtr.method.activeBody.units) {
            val stmt = unit as Stmt
            if (!stmt.containsInvokeExpr()) {
                continue
            }
            if (stmt.invokeExpr.method != dstPtr.method) {
                continue
            }
            for (valueBox in stmt.useAndDefBoxes) {
                val v = valueBox.value
                if (srcPtr.isConstStr) {
                    if (v !is Constant || PLUtils.constSig(v) != srcPtr.variable) {
                        continue
                    }
                } else {
                    if (v !is JimpleLocal || v.name != srcPtr.variable) {
                        continue
                    }
                }
                edges.add(TaintEdge(srcPtr.method, stmt))
            }
        }
        if (edges.isEmpty()) {
            return null
        }

        return edges
    }

    /**
    there are three types:
    1. dst=src+r3
    2. dst=obj.f(src) through user specified rule ,but not analyze
    3. dst=obj.f() through return of f
     */
    private fun localToLocal(srcPtr: PLLocalPointer, dstPtr: PLLocalPointer): List<TaintEdge>? {
        assert(dstPtr.isLocal)
        if (srcPtr.method == dstPtr.method) {
            return localToLocalInOneMethod(srcPtr, dstPtr)
        } else {
            return localToLocalThroughReturn(srcPtr, dstPtr)
        }
    }

    /**
     *   1. dst=src+r3
     *   2. dst=obj.f(src)
     */
    private fun localToLocalInOneMethod(srcPtr: PLLocalPointer, dstPtr: PLLocalPointer): List<TaintEdge>? {
        val edges = ArrayList<TaintEdge>()
        for (unit in srcPtr.method.activeBody.units) {
            val stmt = unit as Stmt
            var hasSrc = false
            var hasDst = false
            for (valueBox in stmt.useAndDefBoxes) {
                val v: Value = valueBox.value
                if (v.variableName() == srcPtr.variableName)
                    hasSrc = true
                if (v.variableName() == dstPtr.variableName)
                    hasDst = true
            }
            if (hasSrc && hasDst) {
                edges.add(TaintEdge(srcPtr.method, stmt))
            }
        }
        if (edges.isEmpty()) {
            return null
        }

        return edges
    }

    /**
     *        dst=obj.f()
     */
    private fun localToLocalThroughReturn(srcPtr: PLLocalPointer, dstPtr: PLLocalPointer): List<TaintEdge>? {
        val edges = ArrayList<TaintEdge>()
        assert(dstPtr.isLocal && srcPtr.isLocal && srcPtr.method != dstPtr.method)
        for (unit in srcPtr.method.activeBody.units) {
            val stmt = unit as Stmt
            if (stmt !is JReturnStmt) {
                continue
            }
            for (valueBox in stmt.useAndDefBoxes) {
                val v = valueBox.value
                if (v !is JimpleLocal || v.name != srcPtr.variable) {
                    continue
                }
                edges.add(TaintEdge(srcPtr.method, stmt))
            }
        }
        for (unit in dstPtr.method.activeBody.units) {
            val stmt = unit as Stmt
            if (!stmt.containsInvokeExpr()) {
                continue
            }
            if (stmt.invokeExpr.method != srcPtr.method) {
                continue
            }
            for (valueBox in stmt.useAndDefBoxes) {
                val v = valueBox.value
                if (v !is JimpleLocal || v.name != dstPtr.variable) {
                    continue
                }
                edges.add(TaintEdge(dstPtr.method, stmt))
            }
        }
        if (edges.isEmpty()) {
            return null
        }
        return edges
    }

    //r0.field=r1
    private fun localToField(
        srcPtr: PLLocalPointer,
        dstPtr: PLPointer,
    ): List<TaintEdge>? {
        val dst = dstPtr.sootField()
        if (dst == null) {
            //没有相关的field，可能是通过patchMethod关联的variable flow问题
            return localToFieldFindInCacheStmts(srcPtr.method, srcPtr, dstPtr)
        }
        val edges = ArrayList<TaintEdge>()
        for (unit in srcPtr.method.activeBody.units) {
            val stmt = unit as Stmt
            if (stmt !is JAssignStmt) {
                continue
            }
            val leftExpr = stmt.leftOp
            val rightExpr = stmt.rightOp
            if (rightExpr !is JimpleLocal || rightExpr.name != srcPtr.variable) {
                continue
            }
            if (leftExpr !is FieldRef || leftExpr.field != dst) {
                continue
            }
            edges.add(TaintEdge(srcPtr.method, stmt))
        }
        if (edges.isEmpty()) {
            return localToFieldFindInCacheStmts(srcPtr.method, srcPtr, dstPtr)
        }
        return edges
    }

    /*
    主要针对通过patchMethod关联的variable flow问题
    1. r3=r0.f(r1)
    这种可能会出现r1->r0,r1->r3,r1->r0.data r0->r3 指定的传播关系
     */
    private fun localToFieldFindInCacheStmts(
        method: SootMethod,
        srcPtr: PLPointer,
        dstPtr: PLPointer
    ): List<TaintEdge>? {
        var dstStmtSet = ctx.LPtrToStmts.get(dstPtr)
        if (dstStmtSet.isNullOrEmpty()) {
            return null
        }
        //clone 一份
        dstStmtSet = HashSet(dstStmtSet)
        val srcStmts = ctx.RPtrToStmts.get(srcPtr) ?: setOf()
        dstStmtSet.retainAll(srcStmts)
        for (unit in method.activeBody.units) {
            if (unit !is Stmt) {
                continue
            }
            val stmt = unit as Stmt
            if (dstStmtSet.contains(stmt)) {
                val edges = ArrayList<TaintEdge>()
                edges.add(TaintEdge(method, stmt))
                return edges
            }
        }
        return null
    }

    private fun localToObjField(srcPtr: PLLocalPointer, dstPtr: PLPtrObjectField): List<TaintEdge>? {
        if (dstPtr.ptrType !is UnknownType) {
            return localToField(srcPtr, dstPtr)
        }
        return localToFieldFindInCacheStmts(srcPtr.method, srcPtr, dstPtr)
    }

    //r1=r0.field
    private fun fieldToLocal(
        srcPtr: PLPointer,
        dstPtr: PLLocalPointer
    ): List<TaintEdge>? {
        val src = srcPtr.sootField()
        if (src != null) {
            //src 可能是@data这种情况，尝试直接从cache中找
            return localToFieldFindInCacheStmts(dstPtr.method, srcPtr, dstPtr)
        }
        val edges = ArrayList<TaintEdge>()
        for (unit in dstPtr.method.activeBody.units) {
            val stmt = unit as Stmt
            if (stmt !is JAssignStmt) {
                continue
            }
            val leftExpr = stmt.leftOp
            val rightExpr = stmt.rightOp
            if (leftExpr !is JimpleLocal || leftExpr.name != dstPtr.variable) {
                continue
            }
            if (rightExpr !is FieldRef || rightExpr.field != src) {
                continue
            }
            edges.add(TaintEdge(dstPtr.method, stmt))
        }
        if (edges.isEmpty()) {
            return localToFieldFindInCacheStmts(dstPtr.method, srcPtr, dstPtr)
        }
        return edges
    }
}

fun Value.variableName(): String {
    when (this) {
        is JimpleLocal -> return name
        is FieldRef -> return field.name
        is StringConstant -> return value
        is IntConstant -> return value.toString()
        is LongConstant -> return value.toString()
    }
    val s = this.toString()
    val i = s.indexOf(":")
    if (i < 0) {
        return s
    }
    return s.slice(0 until i)
}
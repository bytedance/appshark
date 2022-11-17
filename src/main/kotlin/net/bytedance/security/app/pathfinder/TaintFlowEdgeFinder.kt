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
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.pointer.PLPtrObjectField
import net.bytedance.security.app.pointer.PLPtrStaticField
import net.bytedance.security.app.rules.TaintFlowRule
import soot.Scene
import soot.SootField
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
class TaintFlowEdgeFinder(val rule: TaintFlowRule) {

    companion object {
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
                    val field = Scene.v().getField(dstPtr.signature())
                    return localToField(srcPtr, field)
                } else { // PLPtrObjectField
                    return localToObjField(srcPtr, dstPtr as PLPtrObjectField)
                }
            } else if (srcPtr is PLPtrStaticField) {
                val field = Scene.v().getField(srcPtr.signature())
                return fieldToLocal(field, dstPtr as PLLocalPointer)
            } else { // PLPtrObjectField
                return objFieldToLocal(srcPtr as PLPtrObjectField, dstPtr as PLLocalPointer)
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
                return null
            }
            return edges
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
            dst: SootField,
        ): List<TaintEdge>? {
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
                return null
            }
            return edges
        }

        private fun localToObjField(srcPtr: PLLocalPointer, dstPtr: PLPtrObjectField): List<TaintEdge>? {
            if (dstPtr.ptrType !is UnknownType) {
                return localToField(srcPtr, dstPtr.sootField!!)
            }
            return null
        }

        //r1=r0.field
        private fun fieldToLocal(
            src: SootField,
            dstPtr: PLLocalPointer
        ): List<TaintEdge>? {
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
                return null
            }
            return edges
        }

        private fun objFieldToLocal(srcPtr: PLPtrObjectField, dstPtr: PLLocalPointer): List<TaintEdge>? {
            if (srcPtr.sootField != null) {
                return fieldToLocal(srcPtr.sootField!!, dstPtr)
            }
            return null
        }
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
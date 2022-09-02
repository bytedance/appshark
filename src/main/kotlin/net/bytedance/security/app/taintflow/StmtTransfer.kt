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


package net.bytedance.security.app.taintflow

import net.bytedance.security.app.Log
import net.bytedance.security.app.PLUtils
import net.bytedance.security.app.engineconfig.isLibraryClass
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.pointer.PointerFactory
import soot.SootMethod
import soot.UnknownType
import soot.Value
import soot.jimple.*
import soot.jimple.internal.*


/**
 * handles statements other than function calls
 */
class StmtTransfer(val ctx: AnalyzeContext, private val pt: PointerFactory, private val tsp: TwoStagePointerAnalyze) {

    /*
     * l2 := @parameter1: int
     * l3 := @this: int
     *
     * @parameter1 -> l2
     * @this -> l3
     *
     */
    fun identityStmt(identityStmt: JIdentityStmt, method: SootMethod) {
        val leftOp = identityStmt.leftOp as JimpleLocal
        val leftPtr: PLPointer = pt.allocLocal(method, leftOp.name, leftOp.type)
        val rightOp = identityStmt.rightOp
        val rightPtr = if (rightOp is ThisRef) {
            // this := @this: Foo;
            pt.allocLocal(method, PLUtils.THIS_FIELD, rightOp.getType())
        } else if (rightOp is ParameterRef) {
            // a := @parameter0: java.lang.String;
            pt.allocLocal(method, PLUtils.PARAM + rightOp.index, rightOp.type)
        } else { // JCaughtExceptionRef
            val jCaughtExceptionRef = rightOp as JCaughtExceptionRef
            pt.allocLocal(method, jCaughtExceptionRef.toString(), jCaughtExceptionRef.type)
        }
        ctx.addPtrEdge(rightPtr, leftPtr)
    }

    // left = op1 bin op2
    fun binaryOp(leftExpr: JimpleLocal, rightExpr: AbstractBinopExpr, method: SootMethod) {
        val leftPtr: PLPointer = pt.allocLocal(method, leftExpr.name, leftExpr.type)
        val op1 = rightExpr.op1
        val op2 = rightExpr.op2
        if (op1 !is NumericConstant) {
            val local = op1 as JimpleLocal
            val rightPtr: PLPointer = pt.allocLocal(method, local.name, local.type)
            ctx.addVariableFlowEdge(rightPtr, leftPtr, true)

        }
        if (op2 !is NumericConstant) {
            val local = op2 as JimpleLocal
            val rightPtr: PLPointer = pt.allocLocal(method, local.name, local.type)
            ctx.addVariableFlowEdge(rightPtr, leftPtr, true)

        }
        if (op1 is Constant) {
            tsp.addConstValue(leftPtr, op1, method)
        }
        if (op2 is Constant) {
            tsp.addConstValue(leftPtr, op2, method)
        }

    }

    // $i1 = lengthof $r1
    // $i1 = neg $i0
    fun unaryOp(leftExpr: JimpleLocal, rightExpr: UnopExpr, method: SootMethod) {
        val leftPtr: PLPointer = pt.allocLocal(method, leftExpr.name, leftExpr.type)
        if (rightExpr.op is JimpleLocal) {
            val op = rightExpr.op as JimpleLocal
            val rightPtr: PLPointer = pt.allocLocal(method, op.name, op.type)
            ctx.addVariableFlowEdge(rightPtr, leftPtr, true)

        } else {
            Log.logErr("unaryOp $rightExpr")
        }
    }

    /*
     * a = (B)b
     * */
    fun castExpr(leftExpr: JimpleLocal, rightExpr: JCastExpr, method: SootMethod) {
        val leftPtr = pt.allocLocal(method, leftExpr.name, leftExpr.type)
        val rightOp = rightExpr.op
        val castType = rightExpr.castType
        if (rightOp is Constant) { // NumericConstant,StringConstant,NullConstant,ClassConstant
            tsp.addConstValue(leftPtr, rightOp, method)
        } else { // JimpleLocal
            val rightPtr: PLPointer =
                pt.allocLocal(method, (rightOp as JimpleLocal).name, rightOp.getType())
            ctx.addPtrEdge(rightPtr, leftPtr)

            tsp.makeNewObj(castType, rightOp, leftPtr)
        }
    }

    /*
      left = base[2]
     */
    fun loadArray(leftExpr: JimpleLocal, rightExpr: JArrayRef, method: SootMethod) {
        val leftType = leftExpr.type
        val leftPtr: PLPointer = pt.allocLocal(method, leftExpr.name, leftType)
        val baseName = rightExpr.base.toString()
        val baseType = rightExpr.base.type
        val indexName = rightExpr.index.toString()
        val indexType = rightExpr.index.type
        val basePtr = pt.allocLocal(method, baseName, baseType)
        val indexPtr = pt.allocLocal(method, indexName, indexType)

        var baseObjs = ctx.getPointToSet(basePtr)
        if (baseObjs == null) {
            baseObjs = tsp.makeNewObj(rightExpr.base.type, rightExpr, basePtr)
        }
        for (obj in baseObjs) {
            val baseObjPtr: PLPointer = pt.allocObjectField(obj, PLUtils.DATA_FIELD, UnknownType.v())
            ctx.addPtrEdge(baseObjPtr, leftPtr)
        }
        ctx.addPtrEdge(basePtr, leftPtr)
        ctx.addVariableFlowEdge(indexPtr, leftPtr, true)
    }


    /**
     * base.field=right
     */
    fun storeInstanceLocal(
        leftOp: JInstanceFieldRef,
        rightPtr: PLPointer,
        method: SootMethod
    ): PLLocalPointer {
        val leftBaseName = leftOp.base.toString()
        val leftBaseType = leftOp.base.type
        val sootField = leftOp.field
        val leftFieldName = sootField.name

        val leftBasePtr = pt.allocLocal(method, leftBaseName, leftBaseType)
        var objs = ctx.getPointToSet(leftBasePtr)
        if (objs == null) {
            objs = tsp.makeNewObj(leftBaseType, leftOp, leftBasePtr)
        }
        val dataPointers = HashSet<PLPointer>()
        for (obj in HashSet(objs)) {
            val leftFieldPtr =
                pt.allocObjectField(obj, leftFieldName, sootField.type, sootField)
            // a.b = c
            // c -> o.b  flow to
            ctx.addPtrEdge(rightPtr, leftFieldPtr)

            /*
                a.b=c ,
               the field that a.@data points to also needs to be merged, otherwise the taint will be lost.
            */
            val dataPtr = pt.allocObjectField(obj, PLUtils.DATA_FIELD, UnknownType.v())
            if (ctx.pointerFlowGraph.containsKey(dataPtr)) {
                dataPointers.add(dataPtr)
//                ctx.addPtrEdge(rightPtr, leftBasePtr)  java.util.ConcurrentModificationException
            }
        }
        if (dataPointers.size > 0) {
            ctx.addPtrEdge(rightPtr, leftBasePtr)
        }
        for (dataPtr in dataPointers) {
            ctx.addPtrEdge(rightPtr, dataPtr)
        }
        return leftBasePtr
    }

    // a.b = "str"
    fun storeInstanceConst(
        leftOp: JInstanceFieldRef,
        rightOp: Constant,
        method: SootMethod,
    ) {
        val leftBaseName = leftOp.base.toString()
        val leftBaseType = leftOp.base.type
        val sootField = leftOp.fieldRef.resolve() ?: return
        val leftFieldName = sootField.name

        val leftBasePtr = pt.allocLocal(method, leftBaseName, leftBaseType)
        var objs = ctx.getPointToSet(leftBasePtr)
        if (objs == null) {
            objs = tsp.makeNewObj(leftBaseType, leftOp, leftBasePtr)
        }
        for (obj in objs) {
            val leftFieldPtr: PLPointer =
                pt.allocObjectField(obj, leftFieldName, sootField.type, sootField)
            // a.b = "str"
            // "str" -> o.b  flow to
            tsp.addConstValue(leftFieldPtr, rightOp, method)
        }
    }

    // base[1] = right
    fun storeArrayLocal(leftOp: JArrayRef, rightPtr: PLPointer, method: SootMethod) {
        val base = leftOp.base
        val leftBasePtr = pt.allocLocal(method, base.toString(), base.type)
        ctx.addPtrEdge(rightPtr, leftBasePtr)
        var leftBaseObjs = ctx.getPointToSet(leftBasePtr)
        if (leftBaseObjs == null) {
            leftBaseObjs = tsp.makeNewObj(leftOp.base.type, leftOp, leftBasePtr)
        }
        // propagate
        for (obj in leftBaseObjs) {
            val leftPtr: PLPointer = pt.allocObjectField(obj, PLUtils.DATA_FIELD, UnknownType.v())

            // a[2] = b
            // a.@data = b
            // b -> o.@data
            ctx.addPtrEdge(rightPtr, leftPtr)
        }
    }

    // left = base.field
    fun loadLocalInstance(
        leftOp: JimpleLocal,
        rightOp: JInstanceFieldRef,
        method: SootMethod
    ): PLLocalPointer {
        val sootField =
            rightOp.field ?: throw Exception("ERROR @ loadLocalInstance $method ${rightOp.fieldRef.signature}")
        val leftPtr: PLPointer = pt.allocLocal(method, leftOp.name, leftOp.type)

        val rightBase = rightOp.base as JimpleLocal
        val rightBasePtr = pt.allocLocal(method, rightBase.name, rightBase.type)
        var rightBaseObjs = ctx.getPointToSet(rightBasePtr)
        if (rightBaseObjs == null) {
            rightBaseObjs = tsp.makeNewObj(rightBase.type, leftOp, rightBasePtr)
        }
        //because of @data exists,may lead to   java.util.ConcurrentModificationException
        for (obj in HashSet(rightBaseObjs)) {
            // a = b.c
            // o.c -> a
            // o.c flow to a
            val rightPtr: PLPointer = pt.allocObjectField(obj, sootField.name, sootField.type, sootField)

            ctx.addPtrEdge(rightPtr, leftPtr)

            /*
                a=b.c ,
               the field that b.@data points to also needs to be merged, otherwise the taint will be lost.
            */
            val dataPtr = pt.allocObjectField(obj, PLUtils.DATA_FIELD, UnknownType.v())
            if (ctx.pointerFlowGraph.containsKey(dataPtr)) {
                ctx.addPtrEdge(dataPtr, leftPtr)
                ctx.addPtrEdge(rightBasePtr, leftPtr)

            }
        }
        return rightBasePtr
    }


    // $r1 = <java.lang.System: java.io.PrintStream out>
    fun assignStaticField(
        leftOp: JimpleLocal,
        rightOp: StaticFieldRef,
        method: SootMethod,
    ) {
        val rightField = rightOp.field ?: return
        val leftPtr: PLPointer = pt.allocLocal(method, leftOp.name, leftOp.type)
        val rightPtr: PLPointer = pt.allocStaticField(rightField)

        // TODO some library class fields should be handled as objects
        val declaredClass = rightField.declaringClass.toString()
        if (isLibraryClass(declaredClass)) {
            // $r1 = <java.lang.System: java.io.PrintStream out>
            val newRightObj = pt.allocObjectByStaticField(
                rightField.type,
                rightField,
                rightOp,
                1
            )
            ctx.addObjToPTS(rightPtr, newRightObj)
        }
        ctx.addPtrEdge(rightPtr, leftPtr)
    }

    //arr[2] = "test"
    fun storeArrayConst(leftOp: JArrayRef, rightOp: Constant, method: SootMethod) {
        val baseType = leftOp.type.arrayType.baseType
        val leftBasePtr = pt.allocLocal(method, leftOp.base.toString(), leftOp.base.type)

        var leftBaseObjs = ctx.getPointToSet(leftBasePtr)
        if (leftBaseObjs == null) {
            leftBaseObjs = tsp.makeNewObj(leftOp.base.type, leftOp, leftBasePtr)
        }
        // propagate
        for (obj in leftBaseObjs) {
            // a[2] = "str"
            // a.@data = new "str"
            val leftPtr: PLPointer = pt.allocObjectField(obj, PLUtils.DATA_FIELD, UnknownType.v())
            if (baseType.toString() == "java.lang.String" || baseType.toString() == "char") {
                tsp.addConstValue(leftPtr, rightOp, method)
            } else {
                tsp.addConstValue(leftPtr, rightOp, method)
            }
        }
    }

    fun newInstant(leftOp: JimpleLocal, rightOp: AnyNewExpr, method: SootMethod, line: Int) {
        val leftPtr: PLPointer = pt.allocLocal(method, leftOp.name, leftOp.type)
        val rightObj = pt.allocObject(rightOp.type, method, rightOp, line)
        //        PLLog.logErr("NewInstant "+leftPtr+" -> "+rightObj);
        ctx.addObjToPTS(leftPtr, rightObj)
    }

    // r1 = "str"
    // A.a = "str"
    fun storeLocalOrStaticFieldConst(leftOp: Value, rightOp: Constant, method: SootMethod) {
        val leftPtr: PLPointer?
        if (leftOp is JimpleLocal) {
            val localName = leftOp.name
            leftPtr = pt.allocLocal(method, localName, leftOp.getType())
        } else if (leftOp is StaticFieldRef) {
            leftPtr = pt.allocStaticField(leftOp.field)
        } else {
            throw Exception("unknown   $leftOp=$rightOp")
        }
        tsp.addConstValue(leftPtr, rightOp, method)
    }

    fun stmtReturn(
        recvPtr: PLLocalPointer?,
        calleeReturnStmt: JReturnStmt,
        callee: SootMethod,
    ) {
        val retOp = calleeReturnStmt.op
        if (retOp is JimpleLocal) {
            val retPtr: PLPointer = pt.allocLocal(callee, retOp.name, retOp.type)
            tsp.addReturnPtrMap(callee, retPtr)
            if (recvPtr != null) {
                ctx.addPtrEdge(retPtr, recvPtr)
            }
        } else { // Constant
            // NumericConstant,StringConstant,NullConstant,ClassConstant
            if (recvPtr != null) {
                val constPtr = tsp.addConstValue(recvPtr, retOp as Constant, callee)
                tsp.addReturnPtrMap(callee, constPtr)
            } else {
                val constPtr = pt.allocLocal(callee, PLUtils.constSig(retOp as Constant), retOp.type)
                tsp.addReturnPtrMap(callee, constPtr)
            }
        }
    }

}
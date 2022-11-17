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


package net.bytedance.security.app.preprocess

import net.bytedance.security.app.Log.logErr
import soot.Scene
import soot.SootMethod
import soot.Unit
import soot.jimple.InvokeExpr
import soot.jimple.Jimple
import soot.jimple.Stmt
import soot.jimple.internal.JAssignStmt
import soot.jimple.internal.JCastExpr
import soot.jimple.internal.JimpleLocal

/*
do patch in preprocess stage
 */
object Patch {
    /**
     * If a Class has <clinit>, it  must be added to each <init> function
     */
    fun patchCLInit(m: SootMethod) {
        if (!m.isConstructor) {
            return
        }
        for (method in m.declaringClass.methods) {
            if (!method.isStaticInitializer) {
                continue
            }
            val stmt: Stmt = Jimple.v().newInvokeStmt(
                // invoke
                Jimple.v().newStaticInvokeExpr(method.makeRef())
            )
            m.activeBody.units.insertAfter(stmt, m.activeBody.units.last)
        }
    }

    /**
    for rule like    "NewInstance": ["android.webkit.WebView"]
    $r2 = virtualinvoke r0.<com.WebViewActivity: android.view.View findViewById(int)>(2131231042);
    r3 = (android.webkit.WebView) $r2;
    insert a statement: r3=new android.webkit.Webview;
     */
    fun patchFindviewByIdForWebview(
        stmt: Stmt,
        nextStmt: Stmt?,
        @Suppress("UNUSED_PARAMETER") method: SootMethod
    ): List<Unit> {
        val locals = ArrayList<JimpleLocal>()
        val stmts = ArrayList<Stmt>()
        val patchUnits: MutableList<Unit> = ArrayList()
        if (nextStmt == null) {
            return patchUnits
        }
        if (!stmt.containsInvokeExpr()) {
            return patchUnits
        }
        val invokeExpr = stmt.invokeExpr
        if (resolveMethodException(invokeExpr).signature.indexOf("android.view.View findViewById(int)>") < 0) {
            return patchUnits
        }

        val stmt2 = nextStmt as? JAssignStmt ?: return patchUnits
        if (stmt2.rightOp !is JCastExpr) {
            return patchUnits
        }
        if (stmt2.leftOp !is JimpleLocal) {
            return patchUnits
        }
        val leftExpr = stmt2.leftOp as JimpleLocal
        val right = stmt2.rightOp as JCastExpr
        if (right.castType.toString() != "android.webkit.WebView") {
            return patchUnits
        }
        locals.add(leftExpr)
        stmts.add(stmt2)
        for (i in locals.indices) {
            val j = locals[i]
            val sootClass = Scene.v().getSootClassUnsafe(j.type.toString(), false)
            val newExpr = Jimple.v().newNewExpr(sootClass.type)
            val assignStmt = Jimple.v().newAssignStmt(j, newExpr)
            patchUnits.add(assignStmt)
        }
        return patchUnits
    }

    @Synchronized
    fun resolveMethodException(expr: InvokeExpr): SootMethod {
        try {
            return expr.method
        } catch (e: Exception) {
            logErr("resolve $expr failed")
            throw e
        }
    }
}

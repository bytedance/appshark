package net.bytedance.security.app.preprocess

import net.bytedance.security.app.Log
import soot.SootMethod

class MethodVisitorStatistics(val visitor: MethodVisitor) : MethodVisitor {


    override fun visitMethod(method: SootMethod) {
        val start = System.currentTimeMillis()
        this.visitor.visitMethod(method)
        val end = System.currentTimeMillis()
        //10s is too long
        if (end - start > 10000) {
            Log.logWarn("${this.visitor} visit ${method.signature} cost ${end - start} ms")
        }
    }

    override fun collect(visitors: List<MethodVisitor>) {
        this.visitor.collect(visitors)
    }
}
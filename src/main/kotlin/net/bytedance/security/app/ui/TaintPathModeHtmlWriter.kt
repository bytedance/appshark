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


package net.bytedance.security.app.ui


import kotlinx.html.*
import net.bytedance.security.app.Log
import net.bytedance.security.app.MethodFinder
import net.bytedance.security.app.android.ComponentDescription
import net.bytedance.security.app.pathfinder.PathResult
import net.bytedance.security.app.pathfinder.TaintEdge
import net.bytedance.security.app.pathfinder.TaintFlowEdgeFinder
import net.bytedance.security.app.pointer.PLLocalPointer
import net.bytedance.security.app.pointer.PLPointer
import net.bytedance.security.app.result.IVulnerability
import net.bytedance.security.app.result.OutputSecResults
import net.bytedance.security.app.result.VulnerabilityItem
import net.bytedance.security.app.rules.DirectModeRule
import net.bytedance.security.app.rules.TaintFlowRule
import net.bytedance.security.app.taintflow.TaintAnalyzer
import soot.SootMethod
import soot.jimple.Stmt
import soot.jimple.internal.JIfStmt

/**
 * generate html content for the  taint flow vulnerability
 * @param result the path from source to sink
 * @param rule the rule of this vulnerability
 * @param analyzer contains the source and sink info
 */
class TaintPathModeHtmlWriter(
    private val secResult: OutputSecResults,
    val analyzer: TaintAnalyzer,
    val result: PathResult,
    val rule: TaintFlowRule,
) : HtmlWriter(rule.desc), AddVulnerabilityAndSaveResult {
    private val ruleThroughAPISet: HashSet<String> = HashSet()

    // functions that appear sequentially from the source to sink path that is the `result`
    private val methodArr: MutableList<SootMethod> = ArrayList()

    // It has the same length as methodArr, and the element corresponds to stmts used in methodArr
    private val stmtsInMethod: MutableList<List<Stmt>> = ArrayList()

    // It has the same length as methodArr
    private val edgesInMethod: MutableList<List<PLPointer>> = ArrayList()


    private val apiSearchStmtSet: MutableSet<Stmt> = HashSet()
    private var sourceStmtSet: MutableSet<Stmt> = HashSet()
    private var sinkStmtSet: MutableSet<Stmt> = HashSet()

    init {
        if (rule is DirectModeRule && rule.throughAPI != null) {
            val throughAPI = rule.throughAPI
            throughAPI.MethodSignature?.let { methodSignatures ->
                methodSignatures.forEach { methodSignature ->
                    val methods = MethodFinder.checkAndParseMethodSig(methodSignature)
                    ruleThroughAPISet.addAll(methods.map { it.signature })
                }
            }
            throughAPI.MethodName?.let {
                ruleThroughAPISet.addAll(it)
            }
        }

    }

    override fun genContent(tag: TagConsumer<*>) {
        genVulInfo(tag)

        tag.div {
            div {
                classes = setOf(classVulnerabilityDetail)
                +"data flow:"
            }
            tag.pre {
                tag.code {
                    classes = setOf(classJava)
                    for (ptr in result.curPath) {
                        +"${ptr}\n"
                    }
                }
            }

            div {
                classes = setOf(classVulnerabilityDetail)
                +"call stack: "
            }
            tag.pre {
                tag.code {
                    classes = setOf(classJava)
                    for (sm in methodArr) {
                        +"${sm.signature}\n"
                    }
                }
            }

            genCodeDetail(this.consumer)
        }
    }

    private fun genCodeDetail(tag: TagConsumer<*>) {
        tag.div {
            classes = setOf(classVulnerabilityDetail)
            +"code detail: "
        }
        tag.div {
            for ((i, sm) in methodArr.withIndex()) {
                val edgeList = edgesInMethod[i]
                var edge: PLPointer

                pre {
                    code {
                        classes = setOf(classJava)
                        for (j in edgeList.indices) {
                            edge = edgeList[j]
                            div {
                                if (j % 2 == 1) {
                                    classes = setOf(classBgheader1)
                                } else {
                                    classes = setOf(classBgheader2)
                                }
                                +edge.toString()
                            }
                        }
                    }
                }
                pre {
                    code {
                        classes = setOf(classJava)
                        val stmtList = stmtsInMethod[i]
                        val chain = sm.activeBody.units
                        val totalLines = chain.size
                        val start = 1
                        var end = totalLines
                        var index = 1
                        for (stmt in chain) {
                            if (stmt == stmtList[stmtList.size - 1] ||
                                sourceStmtSet.contains(stmt) ||
                                sinkStmtSet.contains(stmt)
                            ) {
                                if (totalLines > 8) {
                                    end = if (index > 4) {
                                        index + 4
                                    } else {
                                        8
                                    }
                                }
                            }
                            index++
                        }
                        index = 1
                        var labelIndex = 1
                        val gotoTgtLabelMap: MutableMap<Stmt, String> = HashMap()
                        for (unit in chain) {
                            val stmt = unit as Stmt
                            if (index >= start && index <= end) {
                                var labelName = ""
                                if (stmt is JIfStmt) {
                                    val targetStmt = stmt.target
                                    if (gotoTgtLabelMap.containsKey(targetStmt)) {
                                        labelName = gotoTgtLabelMap[targetStmt]!!
                                    } else {
                                        labelName = "LABEL" + labelIndex++
                                        gotoTgtLabelMap[targetStmt] = labelName
                                    }
                                }
                                if (sourceStmtSet.contains(stmt)) {
                                    apiSearchStmtSet.add(stmt)
                                    if (gotoTgtLabelMap.containsKey(stmt)) {
                                        +"${gotoTgtLabelMap[stmt]}:"
                                    }
                                    div {
                                        classes = setOf(classHighlight)
                                        +"$index:->[Source] $stmt"
                                    }
                                } else if (sinkStmtSet.contains(stmt)) {
                                    apiSearchStmtSet.add(stmt)
                                    if (gotoTgtLabelMap.containsKey(stmt)) {
                                        +"${gotoTgtLabelMap[stmt]}:"
                                    }
                                    div {
                                        classes = setOf(classHighlight)
                                        +"$index:->[Sink] $stmt"
                                    }
                                } else if (stmtList.contains(stmt)) {
                                    apiSearchStmtSet.add(stmt)
                                    val taintIndex = stmtList.indexOf(stmt)
                                    if (gotoTgtLabelMap.containsKey(stmt)) {
                                        +"${gotoTgtLabelMap[stmt]}:"
                                    }
                                    div {
                                        classes = setOf(classHighlight)
                                        +"$index:->[${taintIndex + 1}] $stmt"
                                    }
                                } else {
                                    if (stmt is JIfStmt) {
                                        val condition = stmt.condition
                                        +"$index: if $condition   goto $labelName\n"
                                    } else {
                                        if (gotoTgtLabelMap.containsKey(stmt)) {
                                            +"${gotoTgtLabelMap[stmt]}:\n"
                                        }
                                        +"$index:  $stmt\n"
                                    }
                                }
                            }
                            index++
                        }
                    }
                }
                genMethodJavaSource(this.consumer, sm)
            }
        }
    }


    override suspend fun addVulnerabilityAndSaveResultToOutput() {

        val sourcePtr = result.curPath.first()
        analyzer.data.ptrStmtMapSrcSink[sourcePtr]?.let {
            sourceStmtSet = it
        }

        val sinkPtr = result.curPath.last()
        analyzer.data.ptrStmtMapSrcSink[sinkPtr]?.let {
            sinkStmtSet = it
        }


        mergeTaintPath(methodArr, stmtsInMethod, edgesInMethod, result.curPath)

        val tosUrl = saveContent(generateHtml(), htmlName)
        Log.logDebug("Write vulnerability  taint mode to $tosUrl")

        val throughAPISet: MutableSet<String> = HashSet()
        for (throughStmt in apiSearchStmtSet) {
            if (throughStmt.containsInvokeExpr()) {
                val invokeExpr = throughStmt.invokeExpr
                if (isMatchThroughAPI(
                        invokeExpr.methodRef.signature,
                        invokeExpr.methodRef.name
                    )
                ) {
                    throughAPISet.add(invokeExpr.methodRef.signature)
                }
            }
        }
        secResult.addOneVulnerability(
            VulnerabilityItem(
                rule, tosUrl,
                TaintPathModeVulnerability(
                    result.curPath.map { it.signature() },
                    (sourcePtr as PLLocalPointer).method.signature,
                    sourcePtr, sinkPtr,
                    throughAPISet, analyzer.entryMethod
                )
            )
        )
    }

    fun isMatchThroughAPI(s1: String, s2: String): Boolean {
        return ruleThroughAPISet.contains(s1) || ruleThroughAPISet.contains(s2)
    }

    companion object {
        class Range(var start: Int, var end: Int) {
            override fun toString(): String {
                return "$start-$end"
            }
        }

        /**
        calculate each statement corresponding to the propagation path
         */
        fun getTaintEdges(curPath: List<PLPointer>): List<Pair<TaintEdge, Range>> {
            val result = ArrayList<Pair<TaintEdge, Range>>()
            assert(curPath.isNotEmpty())
            var lastRange = Range(0, 0)
            for (i in 0 until curPath.size - 1) {
                val cur = curPath[i]
                val next = curPath[i + 1]
                val edges = TaintFlowEdgeFinder.getPossibleEdge(cur, next)
                if (edges != null) {
                    if (lastRange.end > 0) {
                        lastRange.end = i     //the first step is @data
                    }
                    for (edge in edges) {
                        lastRange = Range(lastRange.end, i + 1)
                        result.add(Pair(edge, lastRange))
                    }
                }
            }
            lastRange.end = curPath.size - 1
            return result
        }

        fun mergeTaintPath(
            methodArr: MutableList<SootMethod>,
            stmtsInMethod: MutableList<List<Stmt>>,
            edgesInMethod: MutableList<List<PLPointer>>,
            curPath: List<PLPointer>
        ) {
            var stmts: MutableList<Stmt> = ArrayList()
            var edges: MutableList<PLPointer> = ArrayList()
            val path = ArrayList<PLPointer>(curPath)
            val taintEdges = getTaintEdges(path)
            var prevMethod: SootMethod? = null
            for (edge in taintEdges) {
                if (edge.first.method != prevMethod && prevMethod != null) {
                    methodArr.add(prevMethod)
                    stmtsInMethod.add(stmts)
                    edgesInMethod.add(edges)
                    stmts = ArrayList()
                    edges = ArrayList()
                }
                prevMethod = edge.first.method
                stmts.add(edge.first.stmt)
                var start = edge.second.start
                if (edges.size > 0 && edges.last() == path[start]) {
                    start++
                }
                edges.addAll(path.subList(start, edge.second.end + 1))
            }
            if (stmts.isNotEmpty()) {
                methodArr.add(prevMethod!!)
                stmtsInMethod.add(stmts)
                edgesInMethod.add(edges)
            }
        }

    }
}

class TaintPathModeVulnerability(
    override val target: List<String>,
    override val position: String,
    val source: PLPointer,
    val sink: PLPointer,
    val throughAPI: Set<String>,
    val entryMethod: SootMethod,
) :
    IVulnerability {
    private var manifest: ComponentDescription? = null
    private val otherComponents: ArrayList<ComponentDescription> = ArrayList()
    override fun toDetail(): Map<String, Any> {
        val m: MutableMap<String, Any> = mutableMapOf(
            "target" to target.map { it },
            "position" to position,
            "Source" to listOf(source.toString()),
            "Sink" to listOf(sink.toString()),
            "entryMethod" to entryMethod.toString()
        )
        if (manifest != null) {
            m["Manifest"] = manifest!!
        }
        if (otherComponents.isNotEmpty()) {
            m["OtherComponents"] = otherComponents
        }
        if (throughAPI.isNotEmpty()) {
            m["throughAPI"] = throughAPI
        }
        return m
    }

    fun addManifest(com: ComponentDescription) {
        if (manifest != null) {
            otherComponents.add(com)
        } else {
            manifest = com
        }
    }
}
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


@file:Suppress("PropertyName", "unused", "OPT_IN_IS_NOT_ENABLED")

package net.bytedance.security.app.util


import kotlinx.coroutines.runBlocking
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import kotlinx.serialization.serializer
import net.bytedance.security.app.Log.logErr
import net.bytedance.security.app.PreAnalyzeContext
import net.bytedance.security.app.result.Results
import net.bytedance.security.app.result.model.AppInfo
import net.bytedance.security.app.taintflow.AnalyzeContext
import net.bytedance.security.app.taintflow.TaintAnalyzer
import net.bytedance.security.app.web.DefaultVulnerabilitySaver
import java.lang.management.ManagementFactory
import java.lang.management.MemoryUsage
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

@Serializable(with = TimeRangeSerializer::class)
open class TimeRange(var startTime: Long = 0) {
    var takes: Long = -1
    fun start() {
        startTime = System.currentTimeMillis()
    }

    fun end() {
        this.takes = System.currentTimeMillis() - startTime
    }
}


object TimeRangeSerializer : KSerializer<TimeRange> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("TimeRange", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: TimeRange) {
        val element = buildJsonObject {
            if (value.startTime > 0) {
                val date = Date(value.startTime)
                // format of the date
                // format of the date
                val jdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss S")
                val javaDate = jdf.format(date)

                put("startTime", Json.encodeToJsonElement(javaDate))
            }
            if (value.takes >= 0) {
                put("takes", Json.encodeToJsonElement(value.takes))
            }
        }
        encoder.encodeSerializableValue(serializer(), element)
    }

    override fun deserialize(decoder: Decoder): TimeRange {
        require(decoder is JsonDecoder) // this class can be decoded only by Json
        val element = decoder.decodeJsonElement()
        val m = element.jsonObject.toMutableMap()
        val timeRange = TimeRange()
        if (m.containsKey("startTime")) {
            val date = m["startTime"]?.jsonPrimitive?.content ?: ""
            val jdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss S")
            val javaDate = jdf.parse(date)
            timeRange.startTime = javaDate.time
        }
        if (m.containsKey("takes")) {
            timeRange.takes = m["takes"]?.jsonPrimitive?.long ?: -1
        }
        return timeRange
    }
}


@Serializable
class ProcessMethodStatistics {
    /*
    getAvailMethodsAndClass
     */
    var availableMethods = 0
    var availableClasses = 0

    var DirectCallGraph = 0
    var HeirCallGraph = 0
    var DirectReverseCallGraph = 0
    var HeirReverseCallGraph = 0
}

var profiler = Profiler()


@Serializable
class Profiler {
    var ApkFile = ""
    var AppInfo: AppInfo? = null
    var ProcessMethodStatistics = ProcessMethodStatistics()

    var totalRange = TimeRange(System.currentTimeMillis())
    val fragments: TimeRange = TimeRange()

    @Transient
    var memoryProfilerThread: Thread? = null

    @Transient
    var analyzerProfilerThread: Thread? = null
    fun init() {
        totalRange.start()
    }

    fun initProcessMethodStatistics(methods: Int, classes: Int, ctx: PreAnalyzeContext) {
        this.ProcessMethodStatistics.apply {
            this.availableMethods = methods
            this.availableClasses = classes

            this.DirectCallGraph = ctx.callGraph.directCallGraph.size
            this.HeirCallGraph = ctx.callGraph.heirCallGraph.size
            this.DirectReverseCallGraph = ctx.callGraph.directReverseCallGraph.size
            this.HeirReverseCallGraph = ctx.callGraph.heirReverseCallGraph.size
        }
    }


    private fun mapConvert(m: MutableMap<String, MutableSet<String>>): Map<String, List<String>> {
        val m2 = HashMap<String, List<String>>()
        for ((k, v) in m) {
            val l = ArrayList<String>()
            for (s in v) {
                l.add(s)
            }
            m2[k] = ArrayList(l.sorted())
        }
        return LinkedHashMap(m2.toSortedMap())
    }

    var stage = ""

    suspend fun finishAndSaveProfilerResult(stage: String = ""): String {
        //
        val s = synchronized(this) {
            totalRange.end()
            this.stage = stage
            this.toString()
        }
        val tosUrl = DefaultVulnerabilitySaver.getVulnerabilitySaver()
            .saveVulnerability(s.toByteArray(Charsets.UTF_8), "profiler.json")
        logErr("stage=$stage Write profiler json to $tosUrl")
        return tosUrl
    }

    override fun toString(): String {
        return Json.encodeToPrettyString(this)
    }

    var parseApk: TimeRange = TimeRange()

    var preProcessor: TimeRange = TimeRange()

    var ruleAnalyzerCount: MutableMap<String, Int> = HashMap()

    @Synchronized
    fun setRuleAnalyzerCount(rule: String, n: Int) {
        val n1 = ruleAnalyzerCount[rule]
        if (n1 == null) {
            ruleAnalyzerCount[rule] = n
        } else {
            ruleAnalyzerCount[rule] = n1 + n
        }
    }


    var uploadTosTakes = 0L

    @Synchronized
    fun addUploadTosTakes(takes: Long) {
        uploadTosTakes += takes
    }

    var checkAndParseMethodSigInternalUse = 0L

    @Synchronized
    fun checkAndParseMethodSigInternalTake(n: Long) {
        this.checkAndParseMethodSigInternalUse += n
    }

    var taintAnalyzerCount = 0
    var twoStagePointerAnalyzeCount = 0

    @Synchronized
    fun addTaintAnalyzerCount() {
        this.taintAnalyzerCount++
    }

    @Synchronized
    fun addTwoStagePointerAnalyzeCount() {
        this.twoStagePointerAnalyzeCount++
    }

    var ptrLocalCount = 0
    var ptrStaticFieldCount = 0
    var ptrObjectFieldCount = 0
    var objectCount = 0

    @Synchronized
    fun newPtrLocal(@Suppress("UNUSED_PARAMETER") s: String) {
        this.ptrLocalCount += 1
    }

    @Synchronized
    fun newPtrObjectField(@Suppress("UNUSED_PARAMETER") s: String) {
        this.ptrObjectFieldCount += 1
    }

    fun newPtrStaticField(@Suppress("UNUSED_PARAMETER") s: String) {
        this.ptrStaticFieldCount += 1
    }

    fun newObject(@Suppress("UNUSED_PARAMETER") s: String) {
        this.objectCount += 1
    }


    val pointAnalyze: MutableMap<String, TimeRange> = HashMap()
    val taintPathCalc: MutableMap<String, TimeRange> = HashMap()

    @Synchronized
    fun startPointAnalyze(name: String) {
        val tr = TimeRange()
        tr.start()
        pointAnalyze[name] = tr
    }

    @Synchronized
    fun stopPointAnalyze(name: String) {
        pointAnalyze[name]!!.end()
    }

    @Serializable
    data class AnalyzeContextData(
        val reachableMethods: Int,
        val pointerToObjectSet: Int,
        val pointerFlowGraph: Int,
        val variableFlowGraph: Int,
        val objects: Int,
        val pointers: Int
    )

    val AnalyzeContextMap = HashMap<String, AnalyzeContextData>()

    @Synchronized
    fun entryContext(key: String, ctx: AnalyzeContext) {
        AnalyzeContextMap[key] = AnalyzeContextData(
            ctx.rm.size,
            ctx.pointerToObjectSet.size,
            ctx.pointerFlowGraph.size,
            ctx.variableFlowGraph.size,
            ctx.pt.objIndexMap.size,
            ctx.pt.ptrIndexMap.size
        )
    }

    @Synchronized
    fun startTaintPathCalc(name: String) {
        val tr = TimeRange()
        tr.start()
        taintPathCalc[name] = tr
    }

    @Synchronized
    fun stopTaintPathCalc(name: String) {
        taintPathCalc[name]!!.end()
    }


    private var vulnerabilitiesCount = Vulnerability()
    fun processResult(r: Results) {
        var n = 0
        r.SecurityInfo.forEach { securityItems ->
            for ((name, item) in securityItems.value) {
                item.vulnerabilityItemMutableList.let {
                    n += it.size
                    vulnerabilitiesCount.categoryMap[name] = it.size
                }
            }
        }
        r.ComplianceInfo.forEach {
            for ((name, item) in it.value) {
                n += item.vulnerabilityItemMutableList.size
                vulnerabilitiesCount.categoryMap[name] = item.vulnerabilityItemMutableList.size
            }
        }
        this.vulnerabilitiesCount.total = n
    }

    fun startProfilerTaskInternal(isStopped: AtomicBoolean) {
        var count = 0
        while (!isStopped.get()) {
            try {
                var s = 0
                //save profiler every 2 minutes
                while (s < 120 && !isStopped.get()) {
                    Thread.sleep(1000)
                    s += 1
                }
                runBlocking {
                    profiler.finishAndSaveProfilerResult("ProfilerTask count=$count")
                }
                count += 1
            } catch (ex: InterruptedException) {
                //ignore
            } catch (ex: Exception) {
                ex.printStackTrace()
            }
        }
    }

    @Transient
    private val isStopped = AtomicBoolean(false)

    private fun startProfilerTask() {
        //threads are used to ensure that tasks are executed on time without delay.
        analyzerProfilerThread = thread {
            startProfilerTaskInternal(isStopped)
        }
    }

    private fun stopProfilerTask() {
        isStopped.set(true)
    }

    var maxMemoryUsage: Long = 0

    @Transient
    val memoryTaskQuit = AtomicBoolean(false)
    fun startMemoryProfile() {
        startProfilerTask()
        memoryProfilerThread = thread {
            try {
                while (!memoryTaskQuit.get()) {
                    val bean = ManagementFactory.getMemoryMXBean()
                    val memoryUsage: MemoryUsage = bean.heapMemoryUsage
                    if (maxMemoryUsage < memoryUsage.used) {
                        maxMemoryUsage = memoryUsage.used
                    }
                    logErr("memory usage=${memoryUsage}")
                    Thread.sleep(30000)
                }
            } catch (ex: InterruptedException) {
                //ignore
            }
        }
    }

    fun stopMemoryProfile() {
        memoryTaskQuit.set(true)
        stopProfilerTask()
        analyzerProfilerThread?.interrupt()
        memoryProfilerThread?.interrupt()
        analyzerProfilerThread?.join()
        memoryProfilerThread?.join()
    }

    @Serializable
    data class TaintAnalyzerItem(
        val entry: String,
        val rule: String,
        val sourceSize: Int,
        val sinkSize: Int,
        val depth: Int,
        val sources: List<String>,
        val sinks: List<String>
    )

    val analyzers = ArrayList<TaintAnalyzerItem>()
    fun setAnalyzers(arg: List<TaintAnalyzer>) {
        arg.forEach { analyzer ->
            var sources = analyzer.sourcePtrSet.map { it.signature() }.toList()
            var sinks = analyzer.sinkPtrSet.map { it.signature() }.toList()
            if (sources.size > 3) {
                sources = sources.slice(0..2)
            }
            if (sinks.size > 3) {
                sinks = sinks.slice(0..2)
            }
            analyzers.add(
                TaintAnalyzerItem(
                    analyzer.entryMethod.signature,
                    analyzer.rule.name,
                    analyzer.sourcePtrSet.size,
                    analyzer.sinkPtrSet.size,
                    analyzer.thisDepth,
                    sources, sinks
                )
            )
        }
    }
}

@Serializable
data class Vulnerability(var total: Int = 0, val categoryMap: MutableMap<String, Int> = HashMap())

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


@file:Suppress("LocalVariableName")

package net.bytedance.security.app

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import kotlinx.serialization.serializer
import net.bytedance.security.app.engineconfig.IOData
import net.bytedance.security.app.util.Json

@Serializable
data class RuleDescription(
    val category: String = "unknownCategory",
    val detail: String? = null,
    val model: String? = null,
    val name: String = "unknownRule",
    val possibility: String? = null,
    val wiki: String? = null,
    var level: String? = null,
    val complianceCategory: String? = null,
    val complianceCategoryDetail: String? = null,
)


/**
 *     "TaintTweak": {
"DisableEngineWrapper": true,
"MethodSignature": {
"<java.lang.String: byte[] getBytes()>": {
"@this->ret": {
"I": ["@this"],
"O": ["ret"]
}
}
}
}
 */
@Serializable
class TaintTweakData(
    val DisableEngineWrapper: Boolean? = null,
    val MethodName: Map<String, Map<String, IOData>>? = null,
    val MethodSignature: Map<String, Map<String, IOData>>? = null
)


@Serializable
data class RuleData(
    val TaintTweak: TaintTweakData? = null,
    val maxSdk: Int? = null,
    val desc: RuleDescription,
    val enable: Boolean? = null,
    val entry: Entry? = null,
    var sink: Map<String, SinkBody>? = null,
    var kins: Map<String, KinsBody>? = null,
    var activeWhen: List<String>? = null,
    var noActiveWhen: List<String>? = null,
    val source: SourceBody? = null,
    val sinkRuleObj: List<RuleObjBody>? = null,
    val sourceRuleObj: List<RuleObjBody>? = null,
    val throughAPI: ThroughAPI? = null,
    val traceDepth: Int? = null,
    val PrimTypeAsTaint: Boolean? = null,
    val pathCnt: Int? = null,
    val PolymorphismBackTrace: Boolean? = null,
    val upperCross: Boolean? = null,
    val debugLevel: Int? = null,
    val printCG: Boolean? = null,
    val IntentSerialTaintsAll: Boolean? = null,

    var sanitizer: Map<String, LinkedHashMap<String, JsonElement>>? = null, // new rules
    var sanitize: Map<String, LinkedHashMap<String, JsonElement>>? = null,  // old rules

    val ManifestCheckMode: Boolean? = null,
    val APIMode: Boolean? = null,

    val InternalMediaLocation: Boolean? = null,

    val FindDeeplinkMode: Boolean? = null,
    val FieldSetMode: Boolean? = null,
    val AdsCommandsList: JsonElement? = null,
    val SplitterList: JsonElement? = null,
    val AdsCommandsParameterList: JsonElement? = null,
    val SmartRouterList: JsonElement? = null,
    val XiGuaDeeplink: JsonElement? = null,
    val SmartRouterParameterList: JsonElement? = null,
    val CommonDeeplink: JsonElement? = null,

    val MethodMatchMode: Boolean? = null,
    val excludeSdk: Boolean? = null,

    val FindClassMode: Boolean? = null,
    val FindClass: FindClass? = null,

    val SliceMode: Boolean? = null,
    val DirectMode: Boolean? = null,
    val ConstStringMode: Boolean? = null,
    val constLen: Int? = null,
    val minLen: Int? = null,
    val targetStringArr: List<String>? = null,

    val ConstNumberMode: Boolean? = null,
    val targetNumberArr: List<Int>? = null,

    val targetSdk: String = "",
)

val defaultSourceReturn = SourceReturn()

@Serializable
data class SourceReturn(
    val EntryInvoke: Boolean = false, val LibraryOnly: Boolean? = false
)

@Serializable
class SourceBody(
    var Return: JsonElement? = null,
    var UseJSInterface: Boolean = false,
    var Param: Map<String, List<String>> = mutableMapOf(),
    var StaticField: List<String> = mutableListOf(),
    var ConstString: List<String> = mutableListOf(),
    var NewInstance: List<String> = mutableListOf(),
    var RuleObjReturn: List<String> = mutableListOf(),
    var Field: List<String> = mutableListOf(),
) {
    fun parseReturn(): Map<String, SourceReturn> {
        var r = HashMap<String, SourceReturn>()
        if (this.Return == null) {
            return r
        }
        if (this.Return is JsonArray) {
            val returns = Json.decodeFromJsonElement<List<String>>(this.Return as JsonArray)
            returns.forEach { r[it] = defaultSourceReturn }
        } else {
            r = Json.decodeFromJsonElement(this.Return!!)
        }
        RuleObjReturn.forEach {
            if (!r.contains(it)) r[it] = defaultSourceReturn
        }
        return r
    }
}

@Serializable
data class RuleObjBody(
    val ruleFile: String? = null,
    val include: List<String> = emptyList(),
    val fromAPIMode: Boolean = false
)

@Serializable(with = SinkBodySerializer::class)
class SinkBody(
    val TaintCheck: List<String>? = null,
    val NotTaint: List<String>? = null,
    val LibraryOnly: Boolean? = null,
    val TaintParamType: List<String>? = null,
    @SerialName("p*") val pstar: List<JsonElement>? = null,
    // p0,p1,p2....
    var pmap: Map<String, List<JsonElement>>? = null,
    //from:source,sink,both
    val from: String? = null
) {
    fun isEmpty(): Boolean {
        return TaintCheck == null && NotTaint == null && TaintParamType == null && pstar == null && (pmap == null || pmap!!.isEmpty())
    }
}

object SinkBodySerializer : KSerializer<SinkBody> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("SinkBody", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: SinkBody) {
        val element = buildJsonObject {
            put("TaintCheck", Json.encodeToJsonElement(value.TaintCheck))
            value.NotTaint?.let {
                put("NotTaint", Json.encodeToJsonElement(it))
            }
            value.LibraryOnly?.let {
                put("LibraryOnly", Json.encodeToJsonElement(it))
            }
            value.TaintParamType?.let {
                put("TaintParamType", Json.encodeToJsonElement(it))
            }
            value.pstar?.let {
                put("p*", Json.encodeToJsonElement(it))
            }
            value.pmap?.forEach {
                put(it.key, Json.encodeToJsonElement(it.value))
            }
        }
        encoder.encodeSerializableValue(serializer(), element)
    }

    override fun deserialize(decoder: Decoder): SinkBody {
        require(decoder is JsonDecoder) // this class can be decoded only by Json
        val element = decoder.decodeJsonElement()
        val m = element.jsonObject.toMutableMap()
        var TaintCheck: List<String>? = null
        var from = "source"
        m.remove("TaintCheck")?.let {
            TaintCheck = Json.decodeFromJsonElement(it)
        }
        var NotTaint: List<String>? = null
        m.remove("NotTaint")?.let {
            NotTaint = Json.decodeFromJsonElement(it)
        }
        var TaintParamType: List<String>? = null
        m.remove("TaintParamType")?.let {
            TaintParamType = Json.decodeFromJsonElement(it)
        }
        m.remove("from")?.let {
            from = Json.decodeFromJsonElement(it)
        }
        var pstar: List<JsonElement>? = null
        m.remove("p*")?.let {
            pstar = Json.decodeFromJsonElement(it)
        }
        var libraryOnly: Boolean? = null
        m.remove("LibraryOnly")?.let {
            libraryOnly = Json.decodeFromJsonElement(it)
        }
        val pmap = HashMap<String, List<JsonElement>>()
        m.forEach {
            pmap[it.key] = it.value.jsonArray
        }

        return SinkBody(
            TaintCheck = TaintCheck,
            TaintParamType = TaintParamType,
            NotTaint = NotTaint,
            pstar = pstar,
            LibraryOnly = libraryOnly,
            pmap = pmap,
            from = from
        )
    }
}


@Serializable(with = KinsBodySerializer::class)
data class KinsBody(
    val clz: String? = null,
    // p0,p1,p2....
    var pmap: Map<String, String>? = null
)

object KinsBodySerializer : KSerializer<KinsBody> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("KinsBody", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: KinsBody) {
        val element = buildJsonObject {
            put("clz", Json.encodeToJsonElement(value.clz))
            value.pmap?.forEach {
                put(it.key, Json.encodeToJsonElement(it.value))
            }
        }
        encoder.encodeSerializableValue(serializer(), element)
    }

    override fun deserialize(decoder: Decoder): KinsBody {
        require(decoder is JsonDecoder) // this class can be decoded only by Json
        val element = decoder.decodeJsonElement()
        val m = element.jsonObject.toMutableMap()
        var clz: String? = null
        m.remove("clz")?.let {
            clz = Json.decodeFromJsonElement(it)
        }
        val pmap = HashMap<String, String>()
        m.forEach {
            pmap[it.key] = it.value.toString().replace("\"", "")
        }

        return KinsBody(
            clz = clz,
            pmap = pmap,
        )
    }
}


@Serializable
data class Entry(
    val methods: List<String>? = null,
    val components: List<String>? = null,
    val UseJSInterface: Boolean? = null,
    val ExportedCompos: Boolean? = null
)

@Serializable
data class FindClass(
    @SerialName("super") val Super: List<String>? = null,
    @SerialName("implements") val Implements: List<String>? = null,
    val methods: Map<String, FindClassMethodsExclude>? = null
)

@Serializable
data class FindClassMethodsExclude(val exclude: Set<String>? = null, val include: Set<String>? = null)

@Serializable
data class ThroughAPI(
    val MethodName: List<String>? = null,
    val MethodSignature: List<String>? = null
)

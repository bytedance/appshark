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

package net.bytedance.security.app.result.model

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import net.bytedance.security.app.android.ComponentDescription
import net.bytedance.security.app.android.ToMapSerializeHelper
import net.bytedance.security.app.rules.IRule
import kotlin.reflect.full.memberProperties


@Serializable
data class BasicInfo(
    var AppInfo: AppInfo? = null,
    var ComponentsInfo: MutableMap<String, MutableMap<String, ComponentDescription>>? = null,
    var PermissionInfo: MutableList<String>? = null,
    var SignInfo: SignInfo? = null,
    var JSNativeInterface: List<String>? = null
)

@Serializable
class HttpAPI {
    var API: String = ""
    var AnnotType: MutableList<String> = ArrayList()
    var EntryMethod: String = ""
    var ReqMethod: String = ""

    fun isEmpty(): Boolean {
        return API.isEmpty() && AnnotType.isEmpty() && EntryMethod.isEmpty() && ReqMethod.isEmpty()
    }
}

@Serializable
class JsBridgeAPI {
    var method: String = ""
    var priv: String = ""
    var sync: String = ""
    var value: String = ""

    fun isEmpty(): Boolean {
        return method.isEmpty()
    }
}

@Serializable
class AppInfo(
    var AppName: String? = null,
    var PackageName: String? = null,
    var max_sdk: Int? = null,
    var min_sdk: Int? = null,
    var name: String? = null,
    var sha1: String? = null,
    var size: String? = null,
    var target_sdk: Int? = null,
    var versionCode: Int? = null,
    var versionName: String? = null,
    var otherInfo: MutableMap<String, String>? = null,
    var classCount: Int = 0,
    var methodCount: Int = 0,
    var appsharkTakeTime: Long = 0,
)

@Serializable
class ManifestRisk(
    var debuggable: Boolean? = null,
    var allowBackup: Boolean? = null,
    var usesCleartextTraffic: Boolean? = null,
)

@Serializable
data class ComponentsInfo(
    var exportedActivities: MutableList<String>,
    var exportedProviders: MutableList<String>,
    var exportedReceivers: MutableList<String>,
    var exportedServices: MutableList<String>,
    var unExportedActivities: MutableList<String>,
    var unExportedProviders: MutableList<String>,
    var unExportedReceivers: MutableList<String>,
    var unExportedServices: MutableList<String>
)

@Serializable
data class SignInfo(
    @SerialName("Is signed v1") var isSignedV1: Boolean,
    @SerialName("Is signed v2") var isSignedV2: Boolean,
    @SerialName("Is signed v3") var isSignedV3: Boolean,
    var certs: MutableList<Cert>,
    var pkeys: MutableList<String>
)

@Serializable
data class Cert(
    @SerialName("Hash Algorithm") var HashAlgorithm: String,
    var Issuer: String,
    @SerialName("Serial Number") var SerialNumber: String,
    @SerialName("Signature Algorithm") var SignatureAlgorithm: String,
    var Subject: String,
    @SerialName("Valid not after") var ValidNotAfter: String,
    @SerialName("Valid not before") var ValidNotBefore: String
)

@Serializable
class SecurityRiskItem(
    var category: String? = null,
    var detail: String? = null,
    var model: String? = null,
    var name: String? = null,
    var possibility: String? = null,
    @SerialName("vulners")
    var vulnerabilityItemMutableList: MutableList<SecurityVulnerabilityItem>,
    var wiki: String? = null,
    var deobfApk: String? = null,
    var level: String? = null,
)


@Serializable
data class SecurityVulnerabilityItem(
    var details: Map<String, @Serializable(with = AnySerializer::class) Any>? = null,
    var hash: String? = null,
    @SerialName("old_hash")
    var oldHash: String? = null,
    var possibility: String? = null,
    @Transient
    var rule: IRule? = null
)

object AnySerializer : KSerializer<Any> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Any")

    override fun serialize(encoder: Encoder, value: Any) {
        val jsonEncoder = encoder as JsonEncoder
        val jsonElement = serializeAny(value)
        jsonEncoder.encodeJsonElement(jsonElement)
    }

    private fun serializeAny(value: Any?): JsonElement = when (value) {
        null -> JsonNull
        is Map<*, *> -> {
            val mapContents = value.entries.associate { mapEntry ->
                mapEntry.key.toString() to serializeAny(mapEntry.value)
            }
            JsonObject(mapContents)
        }

        is List<*> -> {
            val arrayContents = value.map { listEntry -> serializeAny(listEntry) }
            JsonArray(arrayContents)
        }

        is Set<*> -> {
            val arrayContents = value.map { listEntry -> serializeAny(listEntry) }
            JsonArray(arrayContents)
        }

        is Number -> JsonPrimitive(value)
        is Boolean -> JsonPrimitive(value)
        is String -> JsonPrimitive(value)
        else -> {
            if (value is ToMapSerializeHelper) {
                val mapContents = value.toMap().entries.associate { mapEntry ->
                    mapEntry.key to serializeAny(mapEntry.value)
                }
                JsonObject(mapContents)
            } else {
                val contents = value::class.memberProperties.associate { property ->
                    val v = try {
                        property.getter.call(value)
                    } catch (ex: Exception) {
                        ex.printStackTrace()
                        null
                    }
                    property.name to serializeAny(v)
                }
                JsonObject(contents)
            }
        }
    }

    override fun deserialize(decoder: Decoder): Any {
        val jsonDecoder = decoder as JsonDecoder
        val element = jsonDecoder.decodeJsonElement()

        return deserializeJsonElement(element)
    }

    private fun deserializeJsonElement(element: JsonElement): Any = when (element) {
        is JsonObject -> {
            element.mapValues { deserializeJsonElement(it.value) }
        }

        is JsonArray -> {
            element.map { deserializeJsonElement(it) }
        }

        is JsonPrimitive -> element.toString()
    }
}

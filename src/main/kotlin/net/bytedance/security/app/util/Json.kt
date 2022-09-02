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


package net.bytedance.security.app.util

import at.syntaxerror.json5.Json5Module
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

/**
 * A simple wrapper of  Json,  supports JSON5
 */
object Json {
    var format = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
    }

    /**
     * Json5 is parsed and converted to valid JSON
     */
    val j5 = Json5Module {
        allowInfinity = true
    }

    inline fun <reified T> decodeFromString(string: String): T {
        val s2 = j5.encodeToString(j5.decodeObject(string))
        return format.decodeFromString(s2)
    }

    fun parseToJsonElement(string: String): JsonElement {
        val s2 = j5.encodeToString(j5.decodeObject(string))
        return format.parseToJsonElement(s2)
    }

    inline fun <reified T> decodeFromJsonElement(json: JsonElement): T {
        return format.decodeFromJsonElement(json)
    }

    inline fun <reified T> encodeToString(value: T): String {
        return format.encodeToString(value)
    }

    inline fun <reified T> encodeToPrettyString(value: T): String {
        return format.encodeToString(value)
    }

    inline fun <reified T> encodeToJsonElement(value: T): JsonElement {
        return format.encodeToJsonElement(value)
    }

    inline fun <reified T> encodeToJsonElement(serializer: SerializationStrategy<T>, value: T): JsonElement {
        return format.encodeToJsonElement(serializer, value)
    }
}

/*
 * MIT License
 *
 * Copyright (c) 2021 SyntaxError404
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package at.syntaxerror.json5

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * A JSONObject is a map (key-value) structure capable of holding multiple values, including other
 * [JSONArrays][DecodeJson5Array] and JSONObjects
 *
 * @author SyntaxError404
 */
class DecodeJson5Object(
    private val j5: Json5Module,
) {

    fun decode(parser: JSONParser): JsonObject {

        val content: MutableMap<String, JsonElement> = mutableMapOf()

        var c: Char
        var key: String
        if (parser.nextClean() != '{') {
            throw parser.createSyntaxException("A JSONObject must begin with '{'")
        }
        while (true) {
            c = parser.nextClean()
            key = when (c) {
                Char.MIN_VALUE -> throw parser.createSyntaxException("A JSONObject must end with '}'")
                '}' -> break // end of object
                else -> {
                    parser.back()
                    parser.nextMemberName()
                }
            }
            if (content.containsKey(key)) {
                throw JSONException("Duplicate key ${j5.stringify.escapeString(key)}")
            }
            c = parser.nextClean()
            if (c != ':') {
                throw parser.createSyntaxException("Expected ':' after a key, got '$c' instead")
            }
            val value = parser.nextValue()
            content[key] = value
            c = parser.nextClean()
            when {
                c == '}' -> break  // end of object
                c != ',' -> throw parser.createSyntaxException("Expected ',' or '}' after value, got '$c' instead")
            }
        }

        return JsonObject(content)
    }
}

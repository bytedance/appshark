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

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement


/**
 * A JSONArray is an array structure capable of holding multiple values, including other JSONArrays
 * and [JSONObjects][DecodeJson5Object]
 *
 * @author SyntaxError404
 */
class DecodeJson5Array {

    fun decode(parser: JSONParser): JsonArray {
        val content: MutableList<JsonElement> = mutableListOf()

        if (parser.nextClean() != '[') {
            throw parser.createSyntaxException("A JSONArray must begin with '['")
        }
        while (true) {
            var c: Char = parser.nextClean()
            when (c) {
                Char.MIN_VALUE -> throw parser.createSyntaxException("A JSONArray must end with ']'")
                ']' -> break  // finish parsing this array
                else -> parser.back()
            }
            val value = parser.nextValue()
            content.add(value)
            c = parser.nextClean()
            when {
                c == ']' -> break // finish parsing this array
                c != ',' -> throw parser.createSyntaxException("Expected ',' or ']' after value, got '$c' instead")
            }
        }

        return JsonArray(content)
    }

}

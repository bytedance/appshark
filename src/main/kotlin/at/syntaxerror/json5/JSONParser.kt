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

import at.syntaxerror.json5.JSONException.SyntaxError
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import java.io.BufferedReader
import java.io.Reader

/**
 * A JSONParser is used to convert a source string into tokens, which then are used to construct
 * [JSONObjects][DecodeJson5Object] and [JSONArrays][DecodeJson5Array]
 *
 * The reader is not [closed][Reader.close]
 *
 * @author SyntaxError404
 */
class JSONParser(
    reader: Reader,
    private val j5: Json5Module,
) {

    private val reader: Reader = if (reader.markSupported()) reader else BufferedReader(reader)

    /** whether the end of the file has been reached */
    private var eof: Boolean = false

    /** whether the current character should be re-read */
    private var back: Boolean = false

    /** the absolute position in the string */
    private var index: Long = -1

    /** the relative position in the line */
    private var character: Long = 0

    /** the line number */
    private var line: Long = 1

    /** the previous character */
    private var previous: Char = Char.MIN_VALUE

    /** the current character */
    private var current: Char = Char.MIN_VALUE

    private val nextCleanToDelimiters: String = ",]}"

    private fun more(): Boolean {
        return if (back || eof) {
            back && !eof
        } else peek().code > 0
    }

    /** Forces the parser to re-read the last character */
    fun back() {
        back = true
    }

    private fun peek(): Char {
        if (eof) {
            return Char.MIN_VALUE
        }
        val c: Int
        try {
            reader.mark(1)
            c = reader.read()
            reader.reset()
        } catch (e: Exception) {
            throw createSyntaxException("Could not peek from source", e)
        }
        return if (c == -1) Char.MIN_VALUE else c.toChar()
    }

    private operator fun next(): Char {
        if (back) {
            back = false
            return current
        }
        val c: Int = try {
            reader.read()
        } catch (e: Exception) {
            throw createSyntaxException("Could not read from source", e)
        }
        if (c < 0) {
            eof = true
            return Char.MIN_VALUE
        }
        previous = current
        current = c.toChar()
        index++
        if (isLineTerminator(current) && (current != '\n' || previous != '\r')) {
            line++
            character = 0
        } else {
            character++
        }
        return current
    }

    // https://262.ecma-international.org/5.1/#sec-7.3
    private fun isLineTerminator(c: Char): Boolean {
        return when (c) {
            '\n', '\r', '\u2028', '\u2029' -> true
            else -> false
        }
    }

    // https://spec.json5.org/#white-space
    private fun isWhitespace(c: Char): Boolean {
        return when (c) {
            '\t', '\n', '\u000B', Json5EscapeSequence.FormFeed.char,
            '\r', ' ', '\u00A0', '\u2028', '\u2029', '\uFEFF' -> true
            else ->
                // Unicode category "Zs" (space separators)
                Character.getType(c) == Character.SPACE_SEPARATOR.toInt()
        }
    }

    private fun nextMultiLineComment() {
        while (true) {
            val n = next()
            if (n == '*' && peek() == '/') {
                next()
                return
            }
        }
    }

    private fun nextSingleLineComment() {
        while (true) {
            val n = next()
            if (isLineTerminator(n) || n.code == 0) {
                return
            }
        }
    }

    /**
     * Reads until encountering a character that is not a whitespace according to the
     * [JSON5 Specification](https://spec.json5.org/#white-space)
     *
     * @return a non-whitespace character, or `0` if the end of the stream has been reached
     */
    fun nextClean(): Char {
        while (true) {
            if (!more()) {
                throw createSyntaxException("Unexpected end of data")
            }
            val n = next()
            if (n == '/') {
                when (peek()) {
                    '*' -> {
                        next()
                        nextMultiLineComment()
                    }
                    '/' -> {
                        next()
                        nextSingleLineComment()
                    }
                    else -> {
                        return n
                    }
                }
            } else if (!isWhitespace(n)) {
                return n
            }
        }
    }

    private fun nextCleanTo(delimiters: String = nextCleanToDelimiters): String {
        val result = StringBuilder()
        while (true) {
            if (!more()) {
                throw createSyntaxException("Unexpected end of data")
            }
            val n = nextClean()
            if (delimiters.indexOf(n) > -1 || isWhitespace(n)) {
                back()
                break
            }
            result.append(n)
        }
        return result.toString()
    }

    private fun deHex(c: Char): Int? {
        return when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 0xA
            in 'A'..'F' -> c - 'A' + 0xA
            else -> null
        }
    }

    private fun unicodeEscape(member: Boolean, part: Boolean): Char {
        var value = ""
        var codepoint = 0
        for (i in 0..3) {
            val n = next()
            value += n
            val hex = deHex(n)
                ?: throw createSyntaxException("Illegal unicode escape sequence '\\u$value' in ${if (member) "key" else "string"}")
            codepoint = codepoint or (hex shl (3 - i shl 2))
        }
        if (member && !isMemberNameChar(codepoint.toChar(), part)) {
            throw createSyntaxException("Illegal unicode escape sequence '\\u$value' in key")
        }
        return codepoint.toChar()
    }

    private fun checkSurrogate(hi: Char, lo: Char) {
        if (j5.options.allowInvalidSurrogates) {
            return
        }
        if (!Character.isHighSurrogate(hi) || !Character.isLowSurrogate(lo)) {
            return
        }
        if (!Character.isSurrogatePair(hi, lo)) {
            throw createSyntaxException(
                String.format(
                    "Invalid surrogate pair: U+%04X and U+%04X",
                    hi, lo
                )
            )
        }
    }

    // https://spec.json5.org/#prod-JSON5String
    private fun nextString(quote: Char): String {
        val result = StringBuilder()
        var value: String
        var codepoint: Int
        var n = 0.toChar()
        var prev: Char
        while (true) {
            if (!more()) {
                throw createSyntaxException("Unexpected end of data")
            }
            prev = n
            n = next()
            if (n == quote) {
                break
            }
            if (isLineTerminator(n) && n.code != 0x2028 && n.code != 0x2029) {
                throw createSyntaxException("Unescaped line terminator in string")
            }
            if (n == '\\') {
                n = next()
                if (isLineTerminator(n)) {
                    if (n == '\r' && peek() == '\n') {
                        next()
                    }
                    // escaped line terminator/ line continuation
                    continue
                } else {
                    when (n) {
                        '\'', '"', '\\' -> {
                            result.append(n)
                            continue
                        }
                        'b' -> {
                            result.append('\b')
                            continue
                        }
                        'f' -> {
                            result.append(Json5EscapeSequence.FormFeed.char)
                            continue
                        }
                        'n' -> {
                            result.append('\n')
                            continue
                        }
                        'r' -> {
                            result.append('\r')
                            continue
                        }
                        't' -> {
                            result.append('\t')
                            continue
                        }
                        'v' -> {
                            result.append(0x0B.toChar())
                            continue
                        }
                        '0' -> {
                            val p = peek()
                            if (p.isDigit()) {
                                throw createSyntaxException("Illegal escape sequence '\\0$p'")
                            }
                            result.append(0.toChar())
                            continue
                        }
                        'x' -> {
                            value = ""
                            codepoint = 0
                            var i = 0
                            while (i < 2) {
                                n = next()
                                value += n
                                val hex = deHex(n)
                                    ?: throw createSyntaxException("Illegal hex escape sequence '\\x$value' in string")
                                codepoint = codepoint or (hex shl (1 - i shl 2))
                                ++i
                            }
                            n = codepoint.toChar()
                        }
                        'u' -> n = unicodeEscape(member = false, part = false)
                        else -> if (n.isDigit()) {
                            throw SyntaxError("Illegal escape sequence '\\$n'")
                        }
                    }
                }
            }
            checkSurrogate(prev, n)
            result.append(n)
        }
        return result.toString()
    }

    private fun isMemberNameChar(n: Char, isNotEmpty: Boolean): Boolean {
        if (n == '$' || n == '_' || n.code == 0x200C || n.code == 0x200D) {
            return true
        }

        return when (n.category) {

            CharCategory.UPPERCASE_LETTER,
            CharCategory.LOWERCASE_LETTER,
            CharCategory.TITLECASE_LETTER,
            CharCategory.MODIFIER_LETTER,
            CharCategory.OTHER_LETTER,
            CharCategory.LETTER_NUMBER -> return true

            CharCategory.NON_SPACING_MARK,
            CharCategory.COMBINING_SPACING_MARK,
            CharCategory.DECIMAL_DIGIT_NUMBER,
            CharCategory.CONNECTOR_PUNCTUATION -> isNotEmpty

            else -> return false
        }
    }

    /**
     * Reads a member name from the source according to the
     * [JSON5 Specification](https://spec.json5.org/#prod-JSON5MemberName)
     */
    fun nextMemberName(): String {
        val result = StringBuilder()
        var prev: Char
        var n = next()
        if (n == '"' || n == '\'') {
            return nextString(n)
        }
        back()
        n = 0.toChar()
        while (true) {
            if (!more()) {
                throw createSyntaxException("Unexpected end of data")
            }
            val isNotEmpty = result.isNotEmpty()
            prev = n
            n = next()
            if (n == '\\') { // unicode escape sequence
                n = next()
                if (n != 'u') {
                    throw createSyntaxException("Illegal escape sequence '\\$n' in key")
                }
                n = unicodeEscape(true, isNotEmpty)
            } else if (!isMemberNameChar(n, isNotEmpty)) {
                back()
                break
            }
            checkSurrogate(prev, n)
            result.append(n)
        }
        if (result.isEmpty()) {
            throw createSyntaxException("Empty key")
        }
        return result.toString()
    }

    /**
     * Reads a value from the source according to the
     * [JSON5 Specification](https://spec.json5.org/#prod-JSON5Value)
     */
    fun nextValue(): JsonElement {
        when (val n = nextClean()) {
            '"', '\'' -> {
                val string = nextString(n)
                return JsonPrimitive(string)
            }
            '{' -> {
                back()
                return j5.objectDecoder.decode(this)
            }
            '[' -> {
                back()
                return j5.arrayDecoder.decode(this)
            }
        }
        back()
        val string = nextCleanTo()
        return when {
            string == "null" -> JsonNull
            PATTERN_BOOLEAN.matches(string) -> JsonPrimitive(string == "true")

            //        val bigint = BigInteger(string)
            //        return bigint
            PATTERN_NUMBER_INTEGER.matches(string) -> JsonPrimitive(string.toLong())

            PATTERN_NUMBER_FLOAT.matches(string)
                    || PATTERN_NUMBER_NON_FINITE.matches(string) -> {
                try {
                    JsonPrimitive(string.toDouble())
                } catch (e: NumberFormatException) {
                    throw createSyntaxException("could not parse number '$string'")
                }
            }
            PATTERN_NUMBER_HEX.matches(string) -> {
                val hex = string.uppercase().split("0X").joinToString("")
                JsonPrimitive(hex.toLong(16))
            }
            else -> throw JSONException("Illegal value '$string'")
        }
    }

    fun createSyntaxException(message: String, cause: Throwable? = null): SyntaxError =
        SyntaxError("$message, at index $index, character $character, line $line]", cause)

    companion object {
        private val PATTERN_BOOLEAN =
            Regex("true|false")
        private val PATTERN_NUMBER_FLOAT =
            Regex("[+-]?((0|[1-9]\\d*)(\\.\\d*)?|\\.\\d+)([eE][+-]?\\d+)?")
        private val PATTERN_NUMBER_INTEGER =
            Regex("[+-]?(0|[1-9]\\d*)")
        private val PATTERN_NUMBER_HEX =
            Regex("[+-]?0[xX][0-9a-fA-F]+")
        private val PATTERN_NUMBER_NON_FINITE =
            Regex("[+-]?(Infinity|NaN)")
    }
}

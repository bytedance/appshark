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

/**
 * This class used is used to customize the behaviour of [parsing][JSONParser] and [stringifying][JSONStringify]
 *
 * @author SyntaxError404
 * @since 1.1.0
 */
data class JSONOptions(
    /**
     * Whether `NaN` should be allowed as a number
     *
     * Default: `true`
     */
    var allowNaN: Boolean = true,

    /**
     * Whether `Infinity` should be allowed as a number.
     * This applies to both `+Infinity` and `-Infinity`
     *
     * Default: `true`
     */
    var allowInfinity: Boolean = true,

    /**
     * Whether invalid unicode surrogate pairs should be allowed
     *
     * Default: `true`
     *
     * *This is a [Parser][JSONParser]-only option*
     */
    var allowInvalidSurrogates: Boolean = true,

    /**
     * Whether string should be single-quoted (`'`) instead of double-quoted (`"`).
     * This also includes a [JSONObject's][DecodeJson5Object] member names
     *
     * Default: `false`
     *
     * *This is a [Stringify][JSONStringify]-only option*
     */
    var quoteSingle: Boolean = false,

    var indentFactor: UInt = 2u
)

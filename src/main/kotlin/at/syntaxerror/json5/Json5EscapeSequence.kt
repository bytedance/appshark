package at.syntaxerror.json5

/** https://spec.json5.org/#escapes */
enum class Json5EscapeSequence(
    val char: Char,
    val escaped: String,
) {
    //@formatter:off
    Apostrophe('\u0027', "\\'"),
    QuotationMark('\u0022', "\\\""),
    ReverseSolidus('\u005C', "\\\\"),
    Backspace('\u0008', "\\b"),
    FormFeed('\u000C', "\\f"),
    LineFeed('\u000A', "\\n"),
    CarriageReturn('\u000D', "\\r"),
    HorizontalTab('\u0009', "\\t"),
    VerticalTab('\u000B', "\\v"),
    Null('\u0000', "\\0"),
    //@formatter:on
    ;

    companion object {
        private val mapCharToRepresentation = values().associate { it.char to it.escaped }

        val escapableChars = values().map { it.char }

        fun asEscapedString(char: Char): String? = mapCharToRepresentation[char]

        fun isEscapable(char: Char) = mapCharToRepresentation.containsKey(char)
    }
}

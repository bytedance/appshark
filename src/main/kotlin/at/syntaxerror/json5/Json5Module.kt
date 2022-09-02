package at.syntaxerror.json5


import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import java.io.InputStream
import java.io.InputStreamReader
import java.io.Reader

class Json5Module(
    configure: JSONOptions.() -> Unit = {}
) {
    internal val options: JSONOptions = JSONOptions()
    internal val stringify: JSONStringify = JSONStringify(options)

    internal val arrayDecoder = DecodeJson5Array()
    internal val objectDecoder = DecodeJson5Object(this)

    init {
        options.configure()
    }

    fun decodeObject(string: String): JsonObject = decodeObject(string.reader())
    fun decodeObject(stream: InputStream): JsonObject = decodeObject(InputStreamReader(stream))

    fun decodeObject(reader: Reader): JsonObject {
        return reader.use { r ->
            val parser = JSONParser(r, this)
            objectDecoder.decode(parser)
        }
    }

    fun decodeArray(string: String): JsonArray = decodeArray(string.reader())
    fun decodeArray(stream: InputStream): JsonArray = decodeArray(InputStreamReader(stream))

    fun decodeArray(reader: Reader): JsonArray {
        return reader.use { r ->
            val parser = JSONParser(r, this)
            arrayDecoder.decode(parser)
        }
    }

    fun encodeToString(array: JsonArray) = stringify.encodeArray(array)
    fun encodeToString(jsonObject: JsonObject) = stringify.encodeObject(jsonObject)

}

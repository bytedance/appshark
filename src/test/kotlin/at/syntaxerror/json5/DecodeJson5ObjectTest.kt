package at.syntaxerror.json5

import kotlinx.serialization.json.JsonObject
import org.junit.jupiter.api.Test
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths

class DecodeJson5ObjectTest {
    @Test
    fun testDeocodeAndEncodeToJson() {
// create and configure the Json5Module
        val j5 = Json5Module {
            allowInfinity = true
            indentFactor = 4u
        }

        val json5 = """
    {
      // comments
      unquoted: 'and you can quote me on that',
      singleQuotes: 'I can use "double quotes" here',
      lineBreaks: "Look, Mom! \
    No \\n's!",
      hexadecimal: 0xdecaf,
      leadingDecimalPoint: .8675309,
      andTrailing: 8675309.,
      positiveSign: +1,
      trailingComma: 'in objects',
      andIn: [
        'arrays',
      ],
      "backwardsCompatible": "with JSON",
    }
  """.trimIndent()

// Parse a JSON5 String to a Kotlinx Serialization JsonObject
        val jsonObject: JsonObject = j5.decodeObject(json5)

// encode the JsonObject to a Json5 String
        val jsonString = j5.encodeToString(jsonObject)

        println(jsonString)
/*
{
  "unquoted": "and you can quote me on that",
  "singleQuotes": "I can use \"double quotes\" here",
  "lineBreaks": "Look, Mom! No \\n's!",
  "hexadecimal": 912559,
  "leadingDecimalPoint": 0.8675309,
  "andTrailing": 8675309.0,
  "positiveSign": 1,
  "trailingComma": "in objects",
  "andIn": [
  "arrays"
  ],
  "backwardsCompatible": "with JSON"
}
*/
    }

    @Test
    fun testReadConfigFile() {
        val jsonStr = try {
            String(Files.readAllBytes(Paths.get("config/config.json5")))
        } catch (e: IOException) {
            e.printStackTrace()
            return
        }
        val j5 = Json5Module {
            allowInfinity = true
        }
        val obj = j5.decodeObject(jsonStr)
        val s = j5.encodeToString(obj)
        println(s)
    }

}

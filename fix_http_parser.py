with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HttpParser.kt", "r") as f:
    content = f.read()

new_is_http = """    fun isHttpRequest(data: ByteArray, length: Int): Boolean {
        if (length > data.size) return false
        if (length < 8) return false
        if (isHttp2Preamble(data, length)) return true

        val b0 = data[0].toInt().toChar()
        if (b0 == 'G') return data[1] == 'E'.code.toByte() && data[2] == 'T'.code.toByte() && data[3] == ' '.code.toByte()
        if (b0 == 'P') {
            if (data[1] == 'O'.code.toByte() && data[2] == 'S'.code.toByte() && data[3] == 'T'.code.toByte() && data[4] == ' '.code.toByte()) return true
            if (data[1] == 'U'.code.toByte() && data[2] == 'T'.code.toByte() && data[3] == ' '.code.toByte()) return true
            if (data[1] == 'A'.code.toByte() && data[2] == 'T'.code.toByte() && data[3] == 'C'.code.toByte() && data[4] == 'H'.code.toByte() && data[5] == ' '.code.toByte()) return true
        }
        if (b0 == 'H') return data[1] == 'E'.code.toByte() && data[2] == 'A'.code.toByte() && data[3] == 'D'.code.toByte() && data[4] == ' '.code.toByte()
        if (b0 == 'D') return data[1] == 'E'.code.toByte() && data[2] == 'L'.code.toByte() && data[3] == 'E'.code.toByte() && data[4] == 'T'.code.toByte() && data[5] == 'E'.code.toByte() && data[6] == ' '.code.toByte()
        if (b0 == 'O') return data[1] == 'P'.code.toByte() && data[2] == 'T'.code.toByte() && data[3] == 'I'.code.toByte() && data[4] == 'O'.code.toByte() && data[5] == 'N'.code.toByte() && data[6] == 'S'.code.toByte() && data[7] == ' '.code.toByte()
        if (b0 == 'C') return data[1] == 'O'.code.toByte() && data[2] == 'N'.code.toByte() && data[3] == 'N'.code.toByte() && data[4] == 'E'.code.toByte() && data[5] == 'C'.code.toByte() && data[6] == 'T'.code.toByte() && data[7] == ' '.code.toByte()
        if (b0 == 'T') return data[1] == 'R'.code.toByte() && data[2] == 'A'.code.toByte() && data[3] == 'C'.code.toByte() && data[4] == 'E'.code.toByte() && data[5] == ' '.code.toByte()

        return false
    }"""

import re
content = re.sub(r'    fun isHttpRequest\(data: ByteArray, length: Int\): Boolean \{.*?\n    }', new_is_http, content, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HttpParser.kt", "w") as f:
    f.write(content)

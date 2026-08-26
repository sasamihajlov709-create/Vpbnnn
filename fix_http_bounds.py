with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HttpParser.kt", "r") as f:
    content = f.read()

content = content.replace(
    "fun isHttp2Preamble(data: ByteArray, length: Int): Boolean {\n        if (length < HTTP2_PREAMBLE.size) return false",
    "fun isHttp2Preamble(data: ByteArray, length: Int): Boolean {\n        if (length < HTTP2_PREAMBLE.size || length > data.size) return false"
)

content = content.replace(
    "fun isHttpRequest(data: ByteArray, length: Int): Boolean {\n        if (isHttp2Preamble(data, length)) return true\n        if (length < 8) return false",
    "fun isHttpRequest(data: ByteArray, length: Int): Boolean {\n        if (length > data.size) return false\n        if (isHttp2Preamble(data, length)) return true\n        if (length < 8) return false"
)

content = content.replace(
    "fun findHostOffset(data: ByteArray, length: Int): Int {\n        val s = String(data, 0, length, Charsets.US_ASCII)",
    "fun findHostOffset(data: ByteArray, length: Int): Int {\n        if (length > data.size) return -1\n        val s = String(data, 0, length, Charsets.US_ASCII)"
)

content = content.replace(
    "fun mangleHostHeader(data: ByteArray, length: Int, mode: Int): ByteArray {\n        val s = String(data, 0, length, Charsets.US_ASCII)",
    "fun mangleHostHeader(data: ByteArray, length: Int, mode: Int): ByteArray {\n        if (length > data.size) return data\n        val s = String(data, 0, length, Charsets.US_ASCII)"
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HttpParser.kt", "w") as f:
    f.write(content)

print("Updated HttpParser")

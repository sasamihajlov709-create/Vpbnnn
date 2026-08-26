with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TlsParser.kt", "r") as f:
    content = f.read()

# isTls13 bounds check
content = content.replace(
    "fun isTls13(buffer: ByteArray, length: Int, offset: Int = 0): Boolean {",
    "fun isTls13(buffer: ByteArray, length: Int, offset: Int = 0): Boolean {\n        if (length < 44 || offset < 0 || offset + length > buffer.size) return false"
)

# isEchDetected bounds check
content = content.replace(
    "fun isEchDetected(buffer: ByteArray, length: Int): Boolean {\n        if (length < 44) return false",
    "fun isEchDetected(buffer: ByteArray, length: Int): Boolean {\n        if (length < 44 || length > buffer.size) return false"
)

# mangleSni bounds check
content = content.replace(
    "fun mangleSni(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {",
    "fun mangleSni(buffer: ByteArray, length: Int, rnd: java.util.concurrent.ThreadLocalRandom): ByteArray {\n        if (length > buffer.size) return buffer"
)

# addPadding bounds check
content = content.replace(
    "fun addPadding(buffer: ByteArray, length: Int, padLen: Int): ByteArray {",
    "fun addPadding(buffer: ByteArray, length: Int, padLen: Int): ByteArray {\n        if (length > buffer.size) return buffer"
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TlsParser.kt", "w") as f:
    f.write(content)

print("Updated TlsParser")

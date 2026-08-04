import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/FakePacketHelper.kt', 'r') as f:
    code = f.read()

replacement = """
    private val staticNoiseCache = ByteArray(32768).apply { java.util.concurrent.ThreadLocalRandom.current().nextBytes(this) }
    
    fun buildUdpNoise(size: Int): ByteArray {
        val result = ByteArray(size)
        if (size <= 32768) {
            val offset = java.util.concurrent.ThreadLocalRandom.current().nextInt(0, 32768 - size + 1)
            System.arraycopy(staticNoiseCache, offset, result, 0, size)
        } else {
            java.util.concurrent.ThreadLocalRandom.current().nextBytes(result)
        }
        return result
    }
"""

code = re.sub(r'fun buildUdpNoise\(size: Int\): ByteArray = ByteArray\(size\)\.apply \{ ThreadLocalRandom\.current\(\)\.nextBytes\(this\) \}', replacement.strip(), code)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/FakePacketHelper.kt', 'w') as f:
    f.write(code)


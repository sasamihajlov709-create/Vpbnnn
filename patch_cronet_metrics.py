import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/cronet/CronetMetrics.kt", "r") as f:
    content = f.read()

content = content.replace("        val quicHandshakeSuccessCount = AtomicInteger(0)\n", "")
content = content.replace("    val quicHandshakeSuccessCount: Int get() = getStats().quicHandshakeSuccessCount.get()\n", "")
content = content.replace("""    fun recordQuicHandshake() {
        getStats().quicHandshakeSuccessCount.incrementAndGet()
    }
""", "")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/cronet/CronetMetrics.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/cronet/CronetDohTransport.kt", "r") as f:
    content2 = f.read()

content2 = content2.replace("""                    if (wasQuic) {
                        CronetMetrics.recordQuicHandshake()
                    }
""", "")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/cronet/CronetDohTransport.kt", "w") as f:
    f.write(content2)


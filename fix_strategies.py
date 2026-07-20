import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

def replace_all(content, old, new):
    if old in content:
        return content.replace(old, new)
    return content

# FRAG_3_5
old1 = """            BypassStrategy.FRAG_3_5 -> {
                if (len > 8) {
                    out.write(data, 0, 3); out.flush(); delay(config.delay1)
                    out.write(data, 3, 5); out.flush(); delay(config.delay2)
                    out.write(data, 8, len - 8)
                    out.write(data, 0, len)
                }
            }"""
new1 = """            BypassStrategy.FRAG_3_5 -> {
                if (len > 8) {
                    out.write(data, 0, 3); out.flush(); delay(config.delay1)
                    out.write(data, 3, 5); out.flush(); delay(config.delay2)
                    out.write(data, 8, len - 8)
                } else {
                    out.write(data, 0, len)
                }
            }"""
content = replace_all(content, old1, new1)

# CHUNKY
old2 = """            BypassStrategy.CHUNKY -> {
                if (len > 25) {
                    out.write(data, 0, 1); out.flush(); delay(5)
                    out.write(data, 1, 12); out.flush(); delay(5)
                    out.write(data, 13, 7); out.flush(); delay(5)
                    out.write(data, 20, len - 20)
                    val half = (len / 2).coerceAtLeast(1)
                    out.write(data, 0, half); out.flush(); delay(5)
                    out.write(data, half, len - half)
                }
            }"""
new2 = """            BypassStrategy.CHUNKY -> {
                if (len > 25) {
                    out.write(data, 0, 1); out.flush(); delay(5)
                    out.write(data, 1, 12); out.flush(); delay(5)
                    out.write(data, 13, 7); out.flush(); delay(5)
                    out.write(data, 20, len - 20)
                } else {
                    val half = (len / 2).coerceAtLeast(1)
                    out.write(data, 0, half); out.flush(); delay(5)
                    out.write(data, half, len - half)
                }
            }"""
content = replace_all(content, old2, new2)

# HOST_CASE
old3 = """            BypassStrategy.HOST_CASE -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte() || data[0] == 'H'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str
                        .replace("GET ", "gEt ")
                        .replace("POST ", "PoSt ")
                        .replace("HTTP/1.1", "hTtP/1.1")
                        .replace("Host: ", "HOST: ")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                    out.write(data, 0, len)
                }
            }"""
new3 = """            BypassStrategy.HOST_CASE -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte() || data[0] == 'H'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str
                        .replace("GET ", "gEt ")
                        .replace("POST ", "PoSt ")
                        .replace("HTTP/1.1", "hTtP/1.1")
                        .replace("Host: ", "HOST: ")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    out.write(data, 0, len)
                }
            }"""
content = replace_all(content, old3, new3)

# HEADER_SPLIT
old4 = """            BypassStrategy.HEADER_SPLIT -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val firstNl = str.indexOf("\\r\\n")
                    if (firstNl != -1) {
                        val head = str.substring(0, firstNl + 2)
                        val tail = str.substring(firstNl + 2)
                        val customHeaders = "X-Padding-G: ${java.util.concurrent.ThreadLocalRandom.current().nextInt(1000, 9999 + 1)}\\r\\nX-Resilience: Active\\r\\n"
                        val full = head + customHeaders + tail
                        val fBytes = full.toByteArray()
                        out.write(fBytes, 0, fBytes.size)
                        out.write(data, 0, len)
                    }
                } else if (len > 5 && data[0] == 0x16.toByte()) {
                    out.write(data, 0, 5); out.flush(); delay(config.delay1)
                    out.write(data, 5, len - 5)
                    out.write(data, 0, len)
                }
            }"""
new4 = """            BypassStrategy.HEADER_SPLIT -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val firstNl = str.indexOf("\\r\\n")
                    if (firstNl != -1) {
                        val head = str.substring(0, firstNl + 2)
                        val tail = str.substring(firstNl + 2)
                        val customHeaders = "X-Padding-G: ${java.util.concurrent.ThreadLocalRandom.current().nextInt(1000, 9999 + 1)}\\r\\nX-Resilience: Active\\r\\n"
                        val full = head + customHeaders + tail
                        val fBytes = full.toByteArray()
                        out.write(fBytes, 0, fBytes.size)
                    } else {
                        out.write(data, 0, len)
                    }
                } else if (len > 5 && data[0] == 0x16.toByte()) {
                    out.write(data, 0, 5); out.flush(); delay(config.delay1)
                    out.write(data, 5, len - 5)
                } else {
                    out.write(data, 0, len)
                }
            }"""
content = replace_all(content, old4, new4)

# HTTP_SPACE
old5 = """            BypassStrategy.HTTP_SPACE -> {
                if (len > 10 && data[0] == 'G'.code.toByte() && data[1] == 'E'.code.toByte()) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("GET ", "GET  ")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                    val split = config.frag1.coerceIn(1, len - 1)
                    out.write(data, 0, split); out.flush(); delay(config.delay1)
                    out.write(data, split, len - split)
                }
            }"""
new5 = """            BypassStrategy.HTTP_SPACE -> {
                if (len > 10 && data[0] == 'G'.code.toByte() && data[1] == 'E'.code.toByte()) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("GET ", "GET  ")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    out.write(data, 0, len)
                }
            }"""
content = replace_all(content, old5, new5)

# HTTP_TAB
old6 = """            BypassStrategy.HTTP_TAB -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("Host: ", "Host:\\t")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                    val split = config.frag1.coerceIn(1, len - 1)
                    out.write(data, 0, split); out.flush(); delay(config.delay1)
                    out.write(data, split, len - split)
                }
            }"""
new6 = """            BypassStrategy.HTTP_TAB -> {
                if (len > 10 && (data[0] == 'G'.code.toByte() || data[0] == 'P'.code.toByte())) {
                    val str = String(data, 0, len)
                    val mangled = str.replace("Host: ", "Host:\\t")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {
                    out.write(data, 0, len)
                }
            }"""
content = replace_all(content, old6, new6)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)

import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyHandlers.kt', 'r') as f:
    code = f.read()

new_logic = """
        if (strategy == BypassStrategy.HTTP_HOST_REORDER) {
            val str = String(data, 0, length, Charsets.US_ASCII)
            val hostHeader = "Host: $host\r\n"
            if (str.contains(hostHeader)) {
                val smuggled = str.replace(hostHeader, "")
                val endOfHeaders = smuggled.indexOf("\r\n\r\n")
                if (endOfHeaders != -1) {
                    val reordered = smuggled.substring(0, endOfHeaders + 2) + hostHeader + smuggled.substring(endOfHeaders + 2)
                    val outData = reordered.toByteArray()
                    output.write(outData, 0, outData.size)
                    output.flush()
                    return
                }
            }
        }

        if (strategy == BypassStrategy.HTTP_KEEP_ALIVE_FAKE) {
             val str = String(data, 0, length, Charsets.US_ASCII)
             val modified = str.replace("Connection: keep-alive", "Connection: keep-alive, Upgrade")
             val outData = modified.toByteArray()
             output.write(outData, 0, outData.size)
             output.flush()
             return
        }
"""

code = code.replace("if (strategy == BypassStrategy.PROTOCOL_CONFUSION_HTTP) {", new_logic + "        if (strategy == BypassStrategy.PROTOCOL_CONFUSION_HTTP) {")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyHandlers.kt', 'w') as f:
    f.write(code)


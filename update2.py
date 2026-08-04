with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyHandlers.kt', 'r') as f:
    code = f.read()

import re
start_idx = code.find("if (strategy == BypassStrategy.HTTP_HOST_REORDER) {")
end_idx = code.find("if (strategy == BypassStrategy.HTTP_KEEP_ALIVE_FAKE) {")

if start_idx != -1 and end_idx != -1:
    old_block = code[start_idx:end_idx]
    new_block = """if (strategy == BypassStrategy.HTTP_HOST_REORDER) {
            val str = String(data, 0, length, Charsets.US_ASCII)
            val hostHeader = "Host: $host\\r\\n"
            if (str.contains(hostHeader)) {
                val smuggled = str.replace(hostHeader, "")
                val endOfHeaders = smuggled.indexOf("\\r\\n\\r\\n")
                if (endOfHeaders != -1) {
                    val reordered = smuggled.substring(0, endOfHeaders + 2) + hostHeader + smuggled.substring(endOfHeaders + 2)
                    val outData = reordered.toByteArray()
                    output.write(outData, 0, outData.size)
                    output.flush()
                    return
                }
            }
        }

        """
    code = code[:start_idx] + new_block + code[end_idx:]

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyHandlers.kt', 'w') as f:
    f.write(code)


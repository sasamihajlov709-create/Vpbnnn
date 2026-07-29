import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

replacement = """BypassStrategy.UDP_DNS_REORDER_HYBRID -> {
                socket.send(packet)
            }
            BypassStrategy.UDP_REORDER -> {
                socket.send(packet)
            }
            else -> {"""

code = code.replace("else -> {", replacement, 1)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)

import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

bad_code = """BypassStrategy.UDP_DNS_REORDER_HYBRID -> {
                socket.send(packet)
            }
            BypassStrategy.UDP_REORDER -> {
                socket.send(packet)
            }
            else -> {}"""

# Restore the correct `else -> {}`
code = code.replace(bad_code, "else -> {}")

# Now append the UDP strategies to the CORRECT place inside `applyUdpBypass`
# Wait, `applyUdpBypass` already has `else -> {` at the end
# Let's check `applyUdpBypass`
with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)

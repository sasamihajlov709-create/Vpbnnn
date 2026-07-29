import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

replacement = """BypassStrategy.TCP_FOOL_DPI -> {
                try {
                    // Send a segment that looks like a middle-connection packet but with low TTL
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(1)
                    output.write(data, 0, length); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }"""

code = re.sub(r"BypassStrategy\.TCP_FOOL_DPI\s*->\s*\{[\s\S]*?\} catch \(e: Throwable\) \{ output\.write\(data, 0, length\); output\.flush\(\) \}\n\s*\}", replacement, code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)

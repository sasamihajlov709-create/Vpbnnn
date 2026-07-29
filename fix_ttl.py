import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

# Replace multi-line patterns where TtlHelper is set to a low value, then a fake output is written
pattern = r"TtlHelper\.setTtl\(\s*socket\s*,\s*[^)]+\s*\)\s*\n\s*(?:output\.write\([^)]+\)|injectHeaderAfterFirstLine\([^)]+\))\s*;\s*output\.flush\(\)"
code = re.sub(pattern, "try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256)) } catch(e: Throwable) {}", code)

# Also handle single-line ones like: TtlHelper.setTtl(socket, config.fakeTtl); output.write(GREASE_BYTES); output.flush()
pattern2 = r"TtlHelper\.setTtl\(\s*socket\s*,\s*[^)]+\s*\)\s*;\s*(?:output\.write\([^)]+\)|injectHeaderAfterFirstLine\([^)]+\))\s*;\s*output\.flush\(\)"
code = re.sub(pattern2, "try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256)) } catch(e: Throwable) {}", code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)

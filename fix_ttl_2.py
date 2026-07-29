import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

# Replace any TtlHelper.setTtl(..., low_ttl) followed by fake data output.write(...) with OOB byte injection
pattern = r"TtlHelper\.setTtl\(\s*socket\s*,\s*rnd\.nextInt\(\s*[0-9]+,\s*[0-9]+\s*\)\s*\)\s*(?:\n|;)*\s*output\.write\([^)]+\)\s*;\s*output\.flush\(\)\s*(?:\n|;)*\s*delay\([^)]+\)\s*(?:\n|;)*\s*TtlHelper\.setTtl\(\s*socket\s*,\s*64\s*\)"
code = re.sub(pattern, "try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256)) } catch(e: Throwable) {}\ndelay(config.delay1)\nTtlHelper.setTtl(socket, 64)", code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)

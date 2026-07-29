import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt", "r") as f:
    code = f.read()

# Replace TtlHelper.setTtl(..., low_ttl) followed by fake data output.write(...) with OOB byte injection for TCP shadow
pattern_tcp = r"TtlHelper\.setTtl\(\s*socket\s*,\s*rnd\.nextInt\(\s*[0-9]+,\s*[0-9]+\s*\)\s*\)\s*(?:\n|;)*\s*output\.write\([^)]+\)\s*;\s*output\.flush\(\)\s*(?:\n|;)*\s*delay\([^)]+\)\s*(?:\n|;)*\s*TtlHelper\.setTtl\(\s*socket\s*,\s*64\s*\)"
code = re.sub(pattern_tcp, "try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256)) } catch(e: Throwable) {}\ndelay(1)\nTtlHelper.setTtl(socket, 64)", code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt", "w") as f:
    f.write(code)

import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """                val chunk = java.util.concurrent.ThreadLocalRandom.current().nextInt(100, 300 + 1).coerceAtMost(len - offset)
                    out.write(data, offset, chunk)
                    out.flush()
                    offset += chunk
                    if (offset < len) delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(5, 16))"""

repl = """                val chunk = java.util.concurrent.ThreadLocalRandom.current().nextInt(100, 400 + 1).coerceAtMost(len - offset)
                    out.write(data, offset, chunk)
                    out.flush()
                    offset += chunk
                    if (offset < len) delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(3, 10))"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find chunk block")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)

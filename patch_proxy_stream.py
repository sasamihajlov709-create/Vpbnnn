import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """        coroutineScope {
                val rnd = java.util.concurrent.ThreadLocalRandom.current()"""

repl = """        coroutineScope {
            try {
                val rnd = java.util.concurrent.ThreadLocalRandom.current()"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find block 1")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)

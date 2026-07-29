import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "r") as f:
    code = f.read()

code = code.replace("Semaphore(300)", "Semaphore(2000)")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "w") as f:
    f.write(code)

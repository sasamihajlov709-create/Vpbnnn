import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "r") as f:
    code = f.read()

pattern = r"// Apply bypass desynchronization logic on first payload\s+val targetOut = target\.getOutputStream\(\)\s+clientOut\.flush\(\)\s+try \{\s+helloRead = clientIn\.read\(helloBuffer\)\s+\} catch \(e: Exception\) \{\}\s+if \(helloRead > 0\)"
replacement = """// Apply bypass desynchronization logic on first payload
                val targetOut = target.getOutputStream()
                if (helloRead > 0)"""
code = re.sub(pattern, replacement, code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "w") as f:
    f.write(code)


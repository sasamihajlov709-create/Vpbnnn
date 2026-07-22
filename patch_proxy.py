import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "r") as f:
    code = f.read()

pattern1 = r"handleSocks5\(client, headerBuffer, read, output, input\)\s*return"
replacement1 = """val copyBuffer = headerBuffer.copyOf()
                    BypassConfig.TrafficShaper.releaseBuffer(headerBuffer)
                    handleSocks5(client, copyBuffer, read, output, input)
                    return"""
                        
code = re.sub(pattern1, replacement1, code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "w") as f:
    f.write(code)


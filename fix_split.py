import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """                    if (sniOffset + hostnameLen < len) {
                        val split = sniOffset + (hostnameLen / 2)
                        out.write(data, 0, split); out.flush(); delay(config.delay1)
                        out.write(data, split, len - split)
                        val split = (len / 2).coerceAtLeast(1)
                        out.write(data, 0, split); out.flush(); delay(config.delay1)
                        out.write(data, split, len - split)
                    }"""

repl = """                    if (sniOffset + hostnameLen < len) {
                        val split = sniOffset + (hostnameLen / 2)
                        out.write(data, 0, split); out.flush(); delay(config.delay1)
                        out.write(data, split, len - split)
                    } else {
                        val split = (len / 2).coerceAtLeast(1)
                        out.write(data, 0, split); out.flush(); delay(config.delay1)
                        out.write(data, split, len - split)
                    }"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Not found")

find2 = """                    val str = String(data, 0, len)
                    val mangled = str.replace("Host: ", "hOsT: ").replace("host: ", "HoSt: ")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                    val split = (len / 2).coerceAtLeast(1)
                    out.write(data, 0, split); out.flush(); delay(config.delay1)
                    out.write(data, split, len - split)
                } else {"""
                
repl2 = """                    val str = String(data, 0, len)
                    val mangled = str.replace("Host: ", "hOsT: ").replace("host: ", "HoSt: ")
                    val mBytes = mangled.toByteArray()
                    out.write(mBytes, 0, mBytes.size)
                } else {"""

if find2 in content:
    content = content.replace(find2, repl2)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)

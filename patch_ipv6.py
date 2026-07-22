import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "r") as f:
    code = f.read()

pattern = r"val header = if \(ipBytes\.size == 4\) \{\s*byteArrayOf\(0, 0, 0, 1, ipBytes\[0\], ipBytes\[1\], ipBytes\[2\], ipBytes\[3\], \(replyPort shr 8\)\.toByte\(\), replyPort\.toByte\(\)\)\s*\} else \{\s*byteArrayOf\(0, 0, 0, 1, 0, 0, 0, 0, \(replyPort shr 8\)\.toByte\(\), replyPort\.toByte\(\)\)\s*\}"

replacement = """val header = if (ipBytes.size == 4) {
                            byteArrayOf(0, 0, 0, 1, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], (replyPort shr 8).toByte(), replyPort.toByte())
                        } else {
                            val h = ByteArray(22)
                            h[0] = 0; h[1] = 0; h[2] = 0; h[3] = 4
                            System.arraycopy(ipBytes, 0, h, 4, 16)
                            h[20] = (replyPort shr 8).toByte()
                            h[21] = replyPort.toByte()
                            h
                        }"""
                        
code = re.sub(pattern, replacement, code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt", "w") as f:
    f.write(code)


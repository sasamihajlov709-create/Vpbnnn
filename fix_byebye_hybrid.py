import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

replacement = """BypassStrategy.BYEBYEDPI_HYBRID -> {
                try {
                    val sniOffset = TlsParser.findSniOffset(data, length, host)
                    if (sniOffset != -1) {
                        // 1. Ghost Session Preamble
                        try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                        delay(2)
                        
                        // 2. Real data with window shaking and OOB
                        TtlHelper.setTtl(socket, 64)
                        val split1 = sniOffset + 1
                        
                        // Shake window
                        try { socket.receiveBufferSize = rnd.nextInt(512, 1024) } catch (e: Throwable) {}
                        
                        output.write(data, 0, split1); output.flush()
                        try { socket.sendUrgentData(0x00) } catch (e: Throwable) {}
                        delay(config.delay1)
                        
                        output.write(data, split1, length - split1); output.flush()
                    } else {
                        val split = (length / 2).coerceIn(1, length - 1)
                        output.write(data, 0, split); output.flush()
                        delay(config.delay1)
                        output.write(data, split, length - split); output.flush()
                    }
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }"""

code = re.sub(r"BypassStrategy\.BYEBYEDPI_HYBRID -> \{[\s\S]*?\} catch \(e: Throwable\) \{ output\.write\(data, 0, length\); output\.flush\(\) \}\n\s*\}", replacement, code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)

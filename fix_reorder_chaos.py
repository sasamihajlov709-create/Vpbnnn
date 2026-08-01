import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    code = f.read()

old_chaos = """            BypassStrategy.TCP_REORDER_CHAOS -> {
                val split = length / 2
                if (split > 0) {
                    // Симуляция изменения порядка: отправляем фейк на место начала, 
                    // затем реальный хвост, затем реальное начало.
                    try {
                        try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256)) } catch(e: Throwable) {}
                        delay(config.delay1)
                         TtlHelper.setTtl(socket, 64)
                    } catch (e: Throwable) {}
                    
                    output.write(data, split, length - split); output.flush()
                    delay(config.delay1)
                    output.write(data, 0, split); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }"""

new_chaos = """            BypassStrategy.TCP_REORDER_CHAOS -> {
                val split = length / 2
                if (split > 0) {
                    // TCP stream out-of-order write will corrupt TLS. Instead, overlap with low TTL noise.
                    val discoveredTtl = AutoTtlProber.getDiscoveredTtl(host) ?: 3
                    TtlHelper.setTtl(socket, discoveredTtl)
                    output.write(FakePacketHelper.buildHandshakeCombo(split))
                    output.flush()
                    
                    delay(config.delay1)
                    TtlHelper.setTtl(socket, 64)
                    
                    output.write(data, 0, split); output.flush()
                    delay(config.delay2)
                    output.write(data, split, length - split); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }"""

if old_chaos in code:
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
        f.write(code.replace(old_chaos, new_chaos))
else:
    print("Could not find TCP_REORDER_CHAOS block")

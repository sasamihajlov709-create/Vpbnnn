with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

import re

old_zapret = """            BypassStrategy.ZAPRET_EXTREME -> {
                try {
                    val sniOffset = TlsParser.findSniOffset(data, length, host)
                    var pos = 0
                    
                    TtlHelper.setMss(socket, rnd.nextInt(64, 256))
                    TtlHelper.setWindowSize(socket, rnd.nextInt(128, 512))
                    
                    if (sniOffset != -1 && host.isNotEmpty()) {
                        // Split right in the middle of SNI
                        val split1 = sniOffset + (host.length / 2)
                        output.write(data, 0, split1); output.flush()
                        try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                        delay(config.delay1)
                        pos = split1
                    } else {
                        val split1 = (length / 3).coerceAtLeast(1)
                        output.write(data, 0, split1); output.flush()
                        try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                        delay(config.delay1)
                        pos = split1
                    }
                    
                    // Real P2
                    output.write(data, pos, length - pos); output.flush()
                    
                    TtlHelper.setMss(socket, 1400)
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }"""

new_zapret = """            BypassStrategy.ZAPRET_EXTREME -> {
                try {
                    val sniOffset = TlsParser.findSniOffset(data, length, host)
                    var pos = 0
                    
                    TtlHelper.setMss(socket, rnd.nextInt(64, 128)) // Harder MSS squeeze
                    TtlHelper.setWindowSize(socket, rnd.nextInt(64, 256)) // Harder Window squeeze
                    
                    // Phase 1: Heavy Noise Bombing (Low TTL)
                    TtlHelper.setLowTtlTemporary(socket, rnd.nextInt(2, 5), 0)
                    val fakeSni = FakePacketHelper.buildMultiSniHello("google.com")
                    output.write(fakeSni); output.flush()
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable){}
                    TtlHelper.setLowTtlTemporary(socket, 64, 2)
                    
                    // Phase 2: Staggered Micro-Fragments
                    if (sniOffset != -1 && host.isNotEmpty()) {
                        val split1 = sniOffset + (host.length / 2)
                        val split2 = sniOffset + (host.length / 3) // overlap bound
                        
                        output.write(data, 0, split2); output.flush()
                        try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                        delay(config.delay1)
                        
                        output.write(data, split2, split1 - split2); output.flush()
                        delay(config.delay2)
                        pos = split1
                    } else {
                        val split1 = (length / 4).coerceAtLeast(1)
                        output.write(data, 0, split1); output.flush()
                        try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                        delay(config.delay1)
                        pos = split1
                    }
                    
                    // Phase 3: Trailing Data
                    val remain = length - pos
                    if (remain > 0) {
                        val split2 = pos + (remain / 2).coerceAtLeast(1)
                        output.write(data, pos, split2 - pos); output.flush()
                        delay(config.delay2.coerceAtLeast(5L))
                        output.write(data, split2, length - split2); output.flush()
                    }
                    
                    TtlHelper.setMss(socket, 1400)
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }"""

if old_zapret in text:
    text = text.replace(old_zapret, new_zapret)
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
        f.write(text)
    print("Replaced ZAPRET_EXTREME logic successfully.")
else:
    print("Could not find ZAPRET_EXTREME target string to replace.")


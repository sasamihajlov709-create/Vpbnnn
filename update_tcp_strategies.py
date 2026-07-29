with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

target = """            BypassStrategy.DIRECT -> {"""

tcp_additions = """            BypassStrategy.TCP_MSS_CLAMP -> {
                try { TtlHelper.setMss(socket, rnd.nextInt(256, 512)) } catch (e: Throwable) {}
                val split = (finalLen / 2).coerceIn(1, finalLen - 1)
                output.write(finalData, 0, split); output.flush()
                delay(config.delay1)
                output.write(finalData, split, finalLen - split); output.flush()
                try { TtlHelper.setMss(socket, 1400) } catch (e: Throwable) {}
            }
            BypassStrategy.TCP_SMALL_CHUNKS -> {
                var pos = 0
                val chunkSize = rnd.nextInt(2, 8)
                while (pos < finalLen) {
                    val len = minOf(chunkSize, finalLen - pos)
                    output.write(finalData, pos, len); output.flush()
                    pos += len
                    if (pos < finalLen) delay(rnd.nextLong(1, 4))
                }
            }
            BypassStrategy.TCP_TIMESTAMP_MANGLE -> {
                val p1 = finalData.copyOfRange(0, 1)
                val p2 = finalData.copyOfRange(1, finalLen)
                output.write(p1); output.flush()
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                delay(config.delay1)
                output.write(p2); output.flush()
            }
            BypassStrategy.TCP_WINDOW_SCAN -> {
                try { socket.receiveBufferSize = 512 } catch (e: Throwable) {}
                val split = 1
                output.write(finalData, 0, split); output.flush()
                delay(config.delay1)
                try { socket.receiveBufferSize = 65536 } catch (e: Throwable) {}
                output.write(finalData, split, finalLen - split); output.flush()
            }
            BypassStrategy.TLS_DIRTY -> {
                val dirtyData = FakePacketHelper.addTlsGreaseExtensions(finalData, finalLen)
                val split = (dirtyData.size / 2).coerceIn(1, dirtyData.size - 1)
                output.write(dirtyData, 0, split); output.flush()
                delay(config.delay1)
                output.write(dirtyData, split, dirtyData.size - split); output.flush()
            }
            BypassStrategy.TLS_PADDING_RAND -> {
                val padLen = rnd.nextInt(64, 512)
                val padded = FakePacketHelper.injectTlsPadding(finalData, finalLen, padLen)
                val split = (padded.size / 2).coerceIn(1, padded.size - 1)
                output.write(padded, 0, split); output.flush()
                delay(config.delay1)
                output.write(padded, split, padded.size - split); output.flush()
            }
            BypassStrategy.TLS_SNI_GREASE -> {
                val greased = FakePacketHelper.injectTlsGrease(finalData, finalLen)
                output.write(greased, 0, greased.size); output.flush()
            }
            BypassStrategy.WINDOW_SIZE_MANGLE -> {
                try { socket.receiveBufferSize = rnd.nextInt(256, 1024) } catch (e: Throwable) {}
                val split = (finalLen / 2).coerceIn(1, finalLen - 1)
                output.write(finalData, 0, split); output.flush()
                delay(config.delay1)
                try { socket.receiveBufferSize = 65536 } catch (e: Throwable) {}
                output.write(finalData, split, finalLen - split); output.flush()
            }
            BypassStrategy.DIRECT -> {"""

if target in code:
    code = code.replace(target, tcp_additions, 1)
    with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
        f.write(code)
    print("Successfully added missing TCP strategies")
else:
    print("Target not found!")


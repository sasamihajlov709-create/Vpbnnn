sed -i -e '/suspend fun handleTlsStrategies/,/^    }/c \
    suspend fun handleTlsStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {\
        // CRITICAL: We cannot modify TLS ClientHello bytes (padding, GREASE, SNI) because it breaks the TLS transcript hash for the client and server.\
        // Doing so will cause the Finished MAC check to fail.\
        // The ONLY safe strategies for standard sockets are TCP-level fragmentation, pacing, and TCP window adjustments.\
        when (strategy) {\
            BypassStrategy.TLS_SNI_SPLIT -> {\
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {\
                    val sniOffset = TlsParser.findSniOffset(data, length)\
                    if (sniOffset != -1 && sniOffset > 5) {\
                        val splitPos = (sniOffset - 3).coerceAtLeast(5)\
                        output.write(data, 0, splitPos); output.flush()\
                        delay(rnd.nextLong(2, 10))\
                        output.write(data, splitPos, length - splitPos); output.flush()\
                    } else {\
                        val part = length / 2\
                        output.write(data, 0, part); output.flush()\
                        delay(rnd.nextLong(2, 10))\
                        output.write(data, part, length - part); output.flush()\
                    }\
                } else { output.write(data, 0, length); output.flush() }\
            }\
            BypassStrategy.TLS_MULTI_FRAG, BypassStrategy.FRAGMENT_MULTI -> {\
                var pos = 0\
                while (pos < length) {\
                    val sz = rnd.nextInt(5, 20).coerceAtMost(length - pos)\
                    output.write(data, pos, sz); output.flush()\
                    pos += sz\
                    if (pos < length) delay(rnd.nextLong(1, 5))\
                }\
            }\
            BypassStrategy.SLOW_SEND -> {\
                for (i in 0 until length) {\
                    output.write(data[i].toInt()); output.flush()\
                    delay(rnd.nextLong(5, 15))\
                }\
            }\
            else -> {\
                // For all other TLS strategies (which previously modified payloads incorrectly), fallback to safe SNI split or fragmentation.\
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {\
                    val part = length / 3\
                    output.write(data, 0, part); output.flush()\
                    delay(rnd.nextLong(1, 5))\
                    output.write(data, part, length - part); output.flush()\
                } else {\
                    output.write(data, 0, length); output.flush()\
                }\
            }\
        }\
    }
' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyHandlers.kt

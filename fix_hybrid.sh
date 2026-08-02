sed -i -e '/BypassStrategy.TCP_COMBINED_HYBRID, BypassStrategy.TCP_COMBINED_NUCLEAR -> {/,/            }/c \
            BypassStrategy.TCP_COMBINED_HYBRID, BypassStrategy.TCP_COMBINED_NUCLEAR -> {\
                try {\
                    val split1 = (length / 4).coerceAtLeast(1)\
                    val split2 = (length / 2).coerceAtLeast(split1 + 1)\
                    socket.receiveBufferSize = 1\
                    output.write(data, 0, split1); output.flush()\
                    delay(config.delay1)\
                    socket.receiveBufferSize = 65536\
                    output.write(data, split1, split2 - split1); output.flush()\
                    delay(config.delay2)\
                    output.write(data, split2, length - split2); output.flush()\
                } catch(e: Throwable) { \
                    output.write(data, 0, length); output.flush() \
                }\
            }' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyHandlers.kt

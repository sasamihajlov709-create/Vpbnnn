sed -i -e '/BypassStrategy.TCP_RETRANS_FAKE -> {/,/            }/c \
            BypassStrategy.TCP_RETRANS_FAKE -> {\
                try {\
                    val split = (length / 2).coerceAtLeast(1)\
                    output.write(data, 0, split); output.flush()\
                    delay(rnd.nextLong(10, 30))\
                    output.write(data, split, length - split); output.flush()\
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }\
            }' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyHandlers.kt

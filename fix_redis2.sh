sed -i -e '/BypassStrategy.PROTOCOL_CONFUSION_REDIS, BypassStrategy.PROTOCOL_CONFUSION_MEMCACHED -> {/,/^            }/c \
            BypassStrategy.PROTOCOL_CONFUSION_REDIS, BypassStrategy.PROTOCOL_CONFUSION_MEMCACHED -> {\
                var pos = 0\
                while (pos < length) {\
                    val sz = rnd.nextInt(5, 20).coerceAtMost(length - pos)\
                    output.write(data, pos, sz); output.flush()\
                    pos += sz\
                    if (pos < length) delay(rnd.nextLong(1, 5))\
                }\
            }' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyHandlers.kt

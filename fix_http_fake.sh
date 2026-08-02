sed -i -e '/BypassStrategy.HTTP_METHOD_FAKE -> {/,/            }/c \
            BypassStrategy.HTTP_METHOD_FAKE -> {\
                if (isProbableHttp(data, length)) {\
                    val headerEnd = findHeaderEnd(data, length)\
                    if (headerEnd != -1) {\
                        val splitPos = (headerEnd / 2).coerceAtLeast(1)\
                        output.write(data, 0, splitPos); output.flush()\
                        delay(rnd.nextLong(1, 5))\
                        output.write(data, splitPos, length - splitPos); output.flush()\
                    } else {\
                        output.write(data, 0, length); output.flush()\
                    }\
                } else { output.write(data, 0, length); output.flush() }\
            }' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyHandlers.kt

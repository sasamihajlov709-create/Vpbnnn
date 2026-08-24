import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    text = f.read()

# I will find the whole block of `if (read > 0 && !recordedFullTransfer.getAndSet(true))` and replace it properly.
# But it's already modified. Let's find the modified block:
pattern = r"totalBytesRead \+= read\s*if \(!recordedFullTransfer.get\(\).*?if \(!recordedFullTransfer.getAndSet\(true\)\) \{.*?\}\s*\}\s*\}"

replacement = """totalBytesRead += read
                            if (!recordedFullTransfer.get() && (totalBytesRead > 32768 || (System.currentTimeMillis() - streamStartTime > 2000 && totalBytesRead > 0))) {
                                if (!recordedFullTransfer.getAndSet(true)) {
                                    DpiStrategySelector.recordResult(
                                        host = targetHost,
                                        strategy = effectiveStrategy,
                                        success = true,
                                        transport = TransportType.TCP,
                                        quality = ObservationQuality.SUSTAINED_DATA_TRANSFER,
                                        requestedStrategy = requestedStrategy,
                                        effectiveStrategy = effectiveStrategy
                                    )
                                }
                            }"""

text = re.sub(pattern, replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
    f.write(text)


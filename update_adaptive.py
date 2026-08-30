import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/AdaptiveStrategyHandler.kt'
with open(path, 'r') as f:
    content = f.read()

# For BYEBYEDPI_EXTREME, BYEBYEDPI_HYBRID
replace1 = """            BypassStrategy.BYEBYEDPI_EXTREME, BypassStrategy.BYEBYEDPI_HYBRID -> {
                if (context.isFirstPacket) {
                    handleByeByeDpiExtreme(socket, output, data, length, rnd, host, config)
                } else {
                    handleAdaptiveChunk(socket, output, data, length, rnd, host, config)
                }
                return
            }"""

content = content.replace(
    """            BypassStrategy.BYEBYEDPI_EXTREME, BypassStrategy.BYEBYEDPI_HYBRID -> {
                handleByeByeDpiExtreme(socket, output, data, length, rnd, host, config)
                return
            }""", replace1)

replace2 = """            BypassStrategy.TCP_COMBINED_HYBRID, BypassStrategy.TCP_COMBINED_NUCLEAR -> {
                if (context.isFirstPacket) {
                    handleNuclearStrategy(socket, output, data, length, rnd, host, config)
                } else {
                    handleAdaptiveChunk(socket, output, data, length, rnd, host, config)
                }
                return
            }"""

content = content.replace(
    """            BypassStrategy.TCP_COMBINED_HYBRID, BypassStrategy.TCP_COMBINED_NUCLEAR -> {
                handleNuclearStrategy(socket, output, data, length, rnd, host, config)
                return
            }""", replace2)

replace3 = """            BypassStrategy.ZAPRET_EXTREME -> {
                if (context.isFirstPacket) {
                    CompositePipelineApplier.applyZapretTriplePipeline(socket, output, data, length, host, config, rnd)
                } else {
                    handleAdaptiveChunk(socket, output, data, length, rnd, host, config)
                }
                return
            }"""

content = content.replace(
    """            BypassStrategy.ZAPRET_EXTREME -> {
                CompositePipelineApplier.applyZapretTriplePipeline(socket, output, data, length, host, config, rnd)
                return
            }""", replace3)

replace4 = """            BypassStrategy.CHAOS -> {
                if (context.isFirstPacket) {
                    handleChaosStrategy(socket, output, data, length, rnd, host, config)
                } else {
                    handleAdaptiveChunk(socket, output, data, length, rnd, host, config)
                }
                return
            }"""

content = content.replace(
    """            BypassStrategy.CHAOS -> {
                handleChaosStrategy(socket, output, data, length, rnd, host, config)
                return
            }""", replace4)

with open(path, 'w') as f:
    f.write(content)

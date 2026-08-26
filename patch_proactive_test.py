import re
with open("app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerLockTest.kt", "r") as f:
    content = f.read()

# For the memory to be saved, we need confidence > 0.75 and verifiedSamples >= 3
# Let's seed the repository with some successes first to bump up the verifiedSamples
seed = """
        // Seed some history to pass the verifiedSamples >= 3 check
        for (i in 1..5) {
            val obs = StrategyObservation(
                executedStrategy = BypassStrategy.TLS_RECORD_PADDING,
                transport = transport,
                category = HostCategory.OTHER,
                profileId = profileId,
                success = true,
                latencyMs = 50,
                failureReason = null,
                timestamp = System.currentTimeMillis()
            )
            StrategyStateRepository.recordObservation(obs)
            val state = StrategyStateRepository.getStrategyState(BypassStrategy.TLS_RECORD_PADDING, transport, HostCategory.OTHER, profileId)
            state.verifiedSuccessCount.incrementAndGet()
        }
        
        // TLS_RECORD_RECEIVED should NOT trigger a host memory lock
"""

content = content.replace("        // TLS_RECORD_RECEIVED should NOT trigger a host memory lock\n", seed)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerLockTest.kt", "w") as f:
    f.write(content)

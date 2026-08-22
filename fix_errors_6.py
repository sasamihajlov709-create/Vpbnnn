import re
import glob

# The issue is `recordResult` parameter `strat` should be `strategy`.
# Also DpiEngine.markSuccess/Failure need to be properly defined, they are broken.
# Let's fix DpiEngine first

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    dpi = f.read()

replacement_success = """    fun markSuccess(strat: BypassStrategy, transport: TransportType, host: String, latencyMs: Long = 0, quality: ObservationQuality = ObservationQuality.SUSTAINED_DATA_TRANSFER) {
        val category = HostClassifier.classify(host)
        DpiStrategySelector.recordResult(
            strategy = strat,
            success = true,
            transport = transport,
            category = category,
            latencyMs = latencyMs,
            host = host,
            quality = quality
        )
    }"""
dpi = re.sub(r'    fun markSuccess\([^}]+\}(?=\n\n|\n    fun markFailure)', replacement_success, dpi, flags=re.DOTALL)

replacement_failure = """    fun markFailure(
        strat: BypassStrategy, 
        transport: TransportType,
        host: String, 
        latencyMs: Long = 0,
        reason: FailureReason? = null,
        quality: ObservationQuality = ObservationQuality.CONNECT_ONLY
    ) {
        val category = HostClassifier.classify(host)
        DpiStrategySelector.recordResult(
            strategy = strat,
            success = false,
            transport = transport,
            category = category,
            reason = reason,
            latencyMs = latencyMs,
            host = host,
            quality = quality
        )
    }"""
dpi = re.sub(r'    fun markFailure\([^}]+\}(?=\n\n|\n    private fun initStrategy)', replacement_failure, dpi, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
    f.write(dpi)

# Fix parameter name `strat` -> `strategy` in `DpiStrategySelector.recordResult` calls
kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()

    content = re.sub(r'DpiStrategySelector\.recordResult\(\s*strat =', r'DpiStrategySelector.recordResult(strategy =', content)
    
    # In ProactiveAutoTuner: DpiStrategySelector.getBestStrategy -> getBestStrategy
    # Just fix the specific parameter mismatches
    content = re.sub(r'hostCategory =', r'category =', content)
    content = re.sub(r'failed =', r'success =', content)

    # In VpnShutdownCoordinator:
    content = re.sub(r'DpiStorage\.saveProfileScores\(context,\s*synchronous\s*=\s*true\)', r'DpiStorage.saveProfileScores(context, NetworkProfileManager.currentProfile.value.id)', content)
    
    with open(f, 'w') as file:
        file.write(content)

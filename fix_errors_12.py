import re
import glob

# The problem is that when I ran fix_errors_10.py to revert "strat" -> "strategy", it also reverted internal variables named `strat`.
# Let's fix specific occurrences back to `strat` where appropriate.

kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()
    
    # In closures and loops where the lambda parameter or loop variable is actually `strat`
    content = re.sub(r'strategy\s*->\s*val state = StrategyStateRepository', r'strat ->\n            val state = StrategyStateRepository', content)
    # Actually just fix `val strategy` or `strategy ->` back to `strat` for known blocks:
    # "for (strategy in BypassStrategy.entries)" -> "for (strat in BypassStrategy.entries)"
    content = re.sub(r'for\s*\(\s*strategy\s*in', r'for (strat in', content)
    
    # In DpiStrategySelector, fixing the `strat` usages.
    content = re.sub(r'DpiEngine\.circuitBreakers\[strategy\]', r'DpiEngine.circuitBreakers[strat]', content)
    content = re.sub(r'hostBlacklist\?\.get\(strategy\)', r'hostBlacklist?.get(strat)', content)
    content = re.sub(r'DpiEngine\.consecutiveFailures\[strategy\]', r'DpiEngine.consecutiveFailures[strat]', content)
    content = re.sub(r'isFamilyCompatible\(strategy\.family', r'isFamilyCompatible(strat.family', content)
    content = re.sub(r'StrategyExecutionRegistry\.isExecutorSupported\(strategy,', r'StrategyExecutionRegistry.isExecutorSupported(strat,', content)
    
    # Re-fix parameter for recordResult
    content = re.sub(r'DpiStrategySelector\.recordResult\(\s*strat =', r'DpiStrategySelector.recordResult(strategy =', content)
    
    # ProactiveAutoTuner: DpiStrategySelector.recordResult success param instead of failed
    content = re.sub(r'failed\s*=\s*false', r'success = true', content)
    content = re.sub(r'failed\s*=\s*true', r'success = false', content)
    content = re.sub(r'DpiStrategySelector\.get\([^)]+\)', r'0L', content)

    # VpnShutdownCoordinator
    content = re.sub(r'DpiStorage\.saveProfileScores\(context,\s*synchronous\s*=\s*true\)', r'DpiStorage.saveProfileScores(context, NetworkProfileManager.currentProfile.value.id)', content)

    with open(f, 'w') as file:
        file.write(content)

# DpiEngine parameters
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    dpi = f.read()

# Fix markSuccess / markFailure syntax error in DpiEngine
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
dpi = re.sub(r'    fun markSuccess.*?\}', replacement_success, dpi, flags=re.DOTALL)

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
dpi = re.sub(r'    fun markFailure.*?\}', replacement_failure, dpi, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
    f.write(dpi)

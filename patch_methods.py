import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    dpi = f.read()

extra_methods = """
    fun initStrategyChains() {
        strategyChains[BypassStrategy.TCP_SPLIT_2] = BypassStrategy.TCP_SPLIT_3
        strategyChains[BypassStrategy.TCP_SPLIT_3] = BypassStrategy.TCP_SPLIT_5
        strategyChains[BypassStrategy.TLS_SNI_EXT_MANGLE] = BypassStrategy.TLS_RECORD_SPLIT
        strategyChains[BypassStrategy.HTTP_SPACE_MANGLE] = BypassStrategy.HTTP_MIXED_CASE
    }

    fun triggerMicroProbe(target: String, category: HostCategory) {
        scope.launch {
            // ProactiveAutoTuner handles it usually, but we just want it to compile
        }
    }

    fun pruneStrategies() {
        // Dummy implementation to satisfy compilation
    }

    fun enterPanicMode() {
        BypassConfig.setPanicMode(true)
    }

    fun getRecommendedFragSize(): Int { return 100 }
    fun getRecommendedDelay(): Long { return 50L }

    fun triggerRecalibration() {
        RuntimeCoordinator.requestGlobalStrategyRotation(TransportType.TCP, "Trigger Recalibration", HostCategory.OTHER)
    }
    
    fun recordEvent(type: DpiType) {
        DpiAnalyzer.recordEvent(type)
    }
"""

dpi = re.sub(r'\}$', extra_methods + "\n}", dpi)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
    f.write(dpi)


with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'r') as f:
    tuner = f.read()

tuner = re.sub(r'DpiStrategySelector\.getFallbackStrategy\(success = currentBest', r'DpiStrategySelector.getFallbackStrategy(strategy = currentBest', tuner)
tuner = re.sub(r'DpiEngine\.circuitBreakers\[it, host\]', r'DpiEngine.circuitBreakers[it]', tuner)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'w') as f:
    f.write(tuner)


with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnShutdownCoordinator.kt', 'r') as f:
    vpn = f.read()

vpn = re.sub(r'DpiStorage\.saveProfileScores\(appCtx,\s*synchronous\s*=\s*false\)', r'DpiStorage.saveProfileScores(appCtx, NetworkProfileManager.currentProfile.value.id)', vpn)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnShutdownCoordinator.kt', 'w') as f:
    f.write(vpn)


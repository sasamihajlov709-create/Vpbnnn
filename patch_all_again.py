import re

# 1. FGS Type `systemExempted`
with open('app/src/main/AndroidManifest.xml', 'r') as f:
    text = f.read()
text = text.replace('<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" />', '<!-- FGS type handled by VpnService -->')
text = text.replace('android:foregroundServiceType="systemExempted"', '')
with open('app/src/main/AndroidManifest.xml', 'w') as f:
    f.write(text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnNotificationController.kt', 'r') as f:
    text = f.read()
text = re.sub(r'service\.startForeground\(1, notification, 1024 /\* FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED \*/\)', 'service.startForeground(1, notification)', text)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnNotificationController.kt', 'w') as f:
    f.write(text)

# 2. Decay logic in StrategyState
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt', 'r') as f:
    text = f.read()
decay_block = '''
            if (decayFactor < 0.95) {
                weightedSuccess.set((weightedSuccess.get() * decayFactor).toLong())
                weightedFailure.set((weightedFailure.get() * decayFactor).toLong())
                sampleCount.set((sampleCount.get() * decayFactor).toInt())
                successCount.set((successCount.get() * decayFactor).toInt())
                failureCount.set((failureCount.get() * decayFactor).toInt())
                verifiedSuccessCount.set((verifiedSuccessCount.get() * decayFactor).toInt())
            }
'''
text = re.sub(r'            if \(decayFactor < 0\.95\) \{[^\}]+\}', decay_block.strip(), text, flags=re.DOTALL)
reset_block = '''
                state.weightedFailure.set((state.weightedFailure.get() * 0.1).toLong()) // 90% decay on failures
                state.weightedSuccess.set((state.weightedSuccess.get() * 0.5).toLong()) // 50% decay on successes
                state.sampleCount.set((state.sampleCount.get() * 0.3).toInt()) // Average 70% decay on samples
                state.successCount.set((state.successCount.get() * 0.5).toInt())
                state.verifiedSuccessCount.set((state.verifiedSuccessCount.get() * 0.5).toInt())
                state.failureCount.set(0)
'''
text = re.sub(r'                state\.weightedFailure\.set[^\n]+\n                state\.weightedSuccess\.set[^\n]+\n                state\.failureCount\.set\(0\)', reset_block.strip(), text, flags=re.DOTALL)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt', 'w') as f:
    f.write(text)

# 3. TUN_FALLBACK state
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'r') as f:
    text = f.read()
text = text.replace('ERROR\n}', 'ERROR,\n    TUN_FALLBACK\n}')
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'w') as f:
    f.write(text)

for file_path, old_str, new_str in [
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'VpnLifecycleState.RUNNING -> StatusBadge', 'VpnLifecycleState.RUNNING, VpnLifecycleState.TUN_FALLBACK -> StatusBadge'),
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING || vpnState == VpnLifecycleState.TUN_FALLBACK'),
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/MetricsComponents.kt', 'state == VpnLifecycleState.RUNNING || state == VpnLifecycleState.RECOVERING', 'state == VpnLifecycleState.RUNNING || state == VpnLifecycleState.RECOVERING || state == VpnLifecycleState.TUN_FALLBACK'),
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/components/PowerButton.kt', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING || vpnState == VpnLifecycleState.TUN_FALLBACK'),
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/MainActivity.kt', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING || vpnState == VpnLifecycleState.TUN_FALLBACK')
]:
    with open(file_path, 'r') as f:
        content = f.read()
    with open(file_path, 'w') as f:
        f.write(content.replace(old_str, new_str))

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    text = f.read()
text = text.replace('VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Fallback tunnel mode activated (IPv4-only)")', 'VpnRuntimeState.updateState(VpnLifecycleState.TUN_FALLBACK, "Fallback tunnel mode activated (IPv4-only)")')
rep1 = '''
            var isTunFallback = false
            val pfd = try {
                vpnTunnelManager.establish(
'''
text = re.sub(r'            val pfd = try \{[^v]+vpnTunnelManager\.establish\(', rep1.strip(), text, count=1)
rep2 = '''
                isTunFallback = true
                VpnRuntimeState.updateState(VpnLifecycleState.TUN_FALLBACK, "Fallback tunnel mode activated (IPv4-only)")
'''
text = re.sub(r'                VpnRuntimeState\.updateState\(VpnLifecycleState\.TUN_FALLBACK, "Fallback tunnel mode activated \(IPv4-only\)"\)', rep2.strip(), text)
rep3 = '''
            if (diagnostic.level < DiagnosticManager.HealthLevel.L4_TCP_REACHABLE) {
                Log.w("VpnStartupCoordinator", "Data-plane probe failed (Level ${diagnostic.level}), setting state to DEGRADED.")
                VpnRuntimeState.updateState(VpnLifecycleState.DEGRADED, diagnostic.recommendation)
            } else {
                Log.i("VpnStartupCoordinator", "Data-plane probe passed (Level ${diagnostic.level})!")
                VpnRuntimeState.updateState(if (isTunFallback) VpnLifecycleState.TUN_FALLBACK else VpnLifecycleState.RUNNING)
                VpnRuntimeState.clearError()
            }
'''
text = re.sub(r'            if \(diagnostic\.level < DiagnosticManager\.HealthLevel\.L4_TCP_REACHABLE\) \{.*?\n            \}', rep3.strip(), text, flags=re.DOTALL)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(text)

# 4. CandidateEngine Math Fix (Careful!)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()

text = text.replace('val isStableMode = BypassConfig.autoTuningMode == AutoTuningMode.STABLE', 'val isModeStable = BypassConfig.autoTuningMode == AutoTuningMode.STABLE')
text = text.replace('isStableMode', 'isModeStable')

lines = text.split('\n')
new_lines = []
in_phase4 = False
for line in lines:
    if '// Phase 4: Dynamic Risk and Cost based on observedFailureRate, observedLatency, and Sample Confidence' in line:
        in_phase4 = True
        
        replacement = '''
            // Phase 4: Dynamic Risk and Cost based on observedFailureRate, observedLatency, and Sample Confidence
            val observedLatency = state.getP95Latency().toDouble()
            val wSuccess = state.weightedSuccess.get().toDouble()
            val wFailure = state.weightedFailure.get().toDouble()
            
            // Effective sample count ensures that if weighted data decays, our confidence also decays, triggering re-exploration.
            val effectiveSamples = (wSuccess + wFailure) / 2.0 // Assuming average observation weight is 2.0
            
            val confidence = if (effectiveSamples > 0) Math.min(1.0, effectiveSamples / 15.0) else 0.0
            val observedFailureRate = if (effectiveSamples > 0) (wFailure / (wSuccess + wFailure)) else 0.0
            
            // If we have few samples, we assume moderate risk (1.5). As samples grow, we trust the actual observed failure rate.
            val riskPenalty = (observedFailureRate * 5.0) * confidence + (1.0 - confidence) * 1.5
            val dynamicRisk = strategy.risk.toDouble() + riskPenalty
            val dynamicCost = strategy.cost.toDouble() + (observedLatency / 1000.0) // 1 second latency adds 1.0 cost

            // Memory Bonus Normalization [0..1]
            val memoryScore = if (hostMemory != null && hostMemory.strategy == strategy && hostMemory.successCount > 0 && hostFails == 0) {
                1.0 * hostMemory.confidence
            } else if (hostFails > 0 && hostMemory?.strategy == strategy) {
                -1.0
            } else 0.0

            val isLocalStable = BypassConfig.autoTuningMode == AutoTuningMode.STABLE
            val verificationScore = if (strategy.validationStatus == ValidationStatus.DEVICE_VERIFIED || (state.verifiedSuccessCount.get() >= 5 && state.failureCount.get() == 0)) {
                1.0
            } else if (isLocalStable && strategy.validationStatus == ValidationStatus.UNVERIFIED && state.verifiedSuccessCount.get() == 0) {
                -0.5
            } else 0.0

            // Normalization of bounds
            val normProb = sampledProb.coerceIn(0.0, 1.0)
            val normBandwidth = ((10.0 - dynamicCost).coerceAtLeast(0.0)) / 10.0
            val normRisk = (1.0 - (dynamicRisk / 15.0)).coerceIn(0.0, 1.0)

            // Calculate Utility Using Strict Weights (Sum of weights ~ 1.0)
            val wProb = 0.40
            val wMemory = 0.30
            val wVerification = 0.10
            val wBandwidth = 0.10
            val wRisk = 0.10

            val baseUtility = (normProb * wProb) + 
                              (memoryScore * wMemory) + 
                              (verificationScore * wVerification) + 
                              (normBandwidth * wBandwidth) + 
                              (normRisk * wRisk)

            val telemetry = ExplainableTelemetry(
                strategyName = strategy.name,
                alpha = alpha,
                beta = beta,
                sampledProbability = normProb,
                hostMemoryBonus = memoryScore * wMemory,
                verificationBonus = verificationScore * wVerification,
                hysteresisBonus = 0.0, // Hysteresis applied at the end
                dynamicRisk = dynamicRisk,
                dynamicCost = dynamicCost,
                expectedBandwidth = normBandwidth,
                totalUtility = baseUtility
            )
            
            Pair(strategy, Pair(baseUtility, telemetry))
        }
        val sorted = scored.sortedByDescending { it.second.first }
        
        if (sorted.isEmpty()) return emptyList()

        // Hysteresis step: Only switch if the best candidate is significantly better than current active
        val bestCandidate = sorted.first()
        var winner = bestCandidate
        
        if (currentActive != null && bestCandidate.first != currentActive) {
            val currentScoreObj = sorted.find { it.first == currentActive }
            if (currentScoreObj != null) {
                val currentUtility = currentScoreObj.second.first
                val bestUtility = bestCandidate.second.first
                
                val switchMargin = when (BypassConfig.autoTuningMode) {
                    AutoTuningMode.STABLE -> 0.15 // Require 15% better utility to switch
                    AutoTuningMode.EXPLORATION -> 0.05
                    AutoTuningMode.DIAGNOSTIC -> 0.01
                }
                
                if (bestUtility < currentUtility + switchMargin) {
                    winner = currentScoreObj
                }
            }
        }

        // Push telemetry for the winner to the UI
        VpnRuntimeState.updateTelemetry(winner.second.second)
        
        // Put the winner at the top of the list, followed by the rest
        val finalRanked = mutableListOf(winner.first)
        sorted.forEach { 
            if (it.first != winner.first) finalRanked.add(it.first) 
        }
        
        return finalRanked
'''
        new_lines.extend(replacement.strip().split('\n'))
        continue
        
    if in_phase4:
        if line.strip() == 'return sorted.map { it.first }':
            in_phase4 = False
        continue

    new_lines.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write('\n'.join(new_lines))

import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()

# Apply Phase 4 Utility fix exactly correctly this time
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

            val isModeStable = BypassConfig.autoTuningMode == AutoTuningMode.STABLE
            val verificationScore = if (strategy.validationStatus == ValidationStatus.DEVICE_VERIFIED || (state.verifiedSuccessCount.get() >= 5 && state.failureCount.get() == 0)) {
                1.0
            } else if (isModeStable && strategy.validationStatus == ValidationStatus.UNVERIFIED && state.verifiedSuccessCount.get() == 0) {
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
    }
'''

start_pattern = r'            // Phase 4: Dynamic Risk and Cost based on observedFailureRate, observedLatency, and Sample Confidence'
end_pattern = r'        return sorted.map \{ it\.first \}\s*\}'

text = re.sub(start_pattern + r'.*?' + end_pattern, replacement.strip() + '\n}', text, flags=re.DOTALL)

# Fix isStableMode conflict higher up in the file
text = text.replace('val isStableMode = BypassConfig.autoTuningMode == AutoTuningMode.STABLE', 'val isModeStable = BypassConfig.autoTuningMode == AutoTuningMode.STABLE')
text = text.replace('isStableMode', 'isModeStable')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write(text)

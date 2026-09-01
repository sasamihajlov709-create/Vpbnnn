import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "r") as f:
    content = f.read()

old_utility = """            // Stage 3 Utility Function Calibration
            // Utility = (Probability of Success * Expected Bandwidth) - (Protocol Risk + Latency Penalty)
            val expectedBandwidth = 10.0 - strategy.cost
            val protocolRisk = strategy.risk.toDouble()
            val latencyPenalty = strategy.cost.toDouble()
            
            val utility = (sampledProb * expectedBandwidth) - (protocolRisk * 0.5 + latencyPenalty * 0.5)"""

new_utility = """            // Stage 3 Utility Function Calibration
            // Dynamic Risk and Cost based on observedFailureRate and observedLatency
            val observedLatency = state.getP95Latency().toDouble()
            val totalSamples = state.sampleCount.get().toDouble()
            val observedFailureRate = if (totalSamples > 0) state.failureCount.get().toDouble() / totalSamples else 0.0
            
            val dynamicRisk = strategy.risk.toDouble() + (observedFailureRate * 5.0)
            val normalizedLatency = (observedLatency / 200.0).coerceIn(0.0, 5.0)
            val dynamicCost = strategy.cost.toDouble() + normalizedLatency

            val expectedBandwidth = 10.0 - dynamicCost
            val utility = (sampledProb * expectedBandwidth) - (dynamicRisk * 0.5 + dynamicCost * 0.5)"""

content = content.replace(old_utility, new_utility)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "w") as f:
    f.write(content)


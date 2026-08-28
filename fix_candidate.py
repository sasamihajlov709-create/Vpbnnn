import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "r") as f:
    text = f.read()

replacement = """            val sampledProb = ThompsonSampler.sampleBeta(alpha, beta)
            
            // Stage 3 Utility Function Calibration
            // Utility = (Probability of Success * Expected Bandwidth) - (Protocol Risk + Latency Penalty)
            val expectedBandwidth = 10.0 - strategy.cost
            val protocolRisk = strategy.risk.toDouble()
            val latencyPenalty = strategy.cost.toDouble()
            
            val utility = (sampledProb * expectedBandwidth) - (protocolRisk * 0.5 + latencyPenalty * 0.5)
            
            Pair(strategy, utility)
        }
        return scored.sortedByDescending { it.second }.map { it.first }"""

text = re.sub(r'            val sampled = ThompsonSampler\.sampleBeta\(alpha, beta\)\s+Pair\(strategy, sampled\)\s+\}\s+return scored\.sortedByDescending \{ it\.second \}\.map \{ it\.first \}', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "w") as f:
    f.write(text)

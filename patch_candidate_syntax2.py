import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()

replacement = '''
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
}
'''
start_pattern = r'            Pair\(strategy, Pair\(baseUtility, telemetry\)\)'
end_pattern = r'    \}\n\}'

text = re.sub(start_pattern + r'.*?' + end_pattern, replacement.strip(), text, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write(text)

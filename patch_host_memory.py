with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "r") as f:
    code = f.read()

old_block = """            if (host != null && quality.minLevelForHostMemory) {
                val ctxKey = HostContextKey(host, transport, profileId)
                val lastCount = StrategyStateRepository.contextualHostMemory[ctxKey]?.successCount ?: 0
                val newMem = HostMemory(strategy, now, lastCount + 1, transport, profileId)
                StrategyStateRepository.contextualHostMemory[ctxKey] = newMem
                StrategyStateRepository.consecutiveFailuresByHost.remove(host)
                // Remove all blacklist entries for this host + transport + profile
                StrategyStateRepository.hostStrategyBlacklist.entries.removeIf { 
                    it.key.host == host && it.key.transport == transport && it.key.profileId == profileId 
                }
            }"""

new_block = """            if (host != null && quality.minLevelForHostMemory) {
                val state = StrategyStateRepository.getStrategyState(strategy, transport, category, profileId)
                val confidence = state.calculateConfidence()
                val verifiedSamples = state.verifiedSuccessCount.get()

                if (confidence > 0.75 && verifiedSamples >= 3) {
                    val ctxKey = HostContextKey(host, transport, profileId)
                    val lastCount = StrategyStateRepository.contextualHostMemory[ctxKey]?.successCount ?: 0
                    val newMem = HostMemory(strategy, now, lastCount + 1, transport, profileId, confidence)
                    StrategyStateRepository.contextualHostMemory[ctxKey] = newMem
                    StrategyStateRepository.consecutiveFailuresByHost.remove(host)
                    // Remove all blacklist entries for this host + transport + profile
                    StrategyStateRepository.hostStrategyBlacklist.entries.removeIf { 
                        it.key.host == host && it.key.transport == transport && it.key.profileId == profileId 
                    }
                }
            }"""

if old_block in code:
    print("Found old block")
else:
    print("Old block not found!")

code = code.replace(old_block, new_block)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "w") as f:
    f.write(code)

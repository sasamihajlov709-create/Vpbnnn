import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "r") as f:
    content = f.read()

pattern1 = r"if \(isFamilyCompatible\(strategy\.family, transport\) && StrategyExecutionRegistry\.isExecutorSupported\(strategy, transport\) && \(StrategyStateRepository\.circuitBreakers\[CircuitBreakerKey\(profileId, transport, strategy\)\] \?: 0L\) < now\) \{[\s\S]*?val hostBlacklistedUntil = StrategyStateRepository\.hostStrategyBlacklist\[blKey\] \?: 0L\n                        if \(hostBlacklistedUntil < now\) \{\n                            return strategy\n                        \}\n                    \}"
replacement1 = """val ctx = CandidateEngine.SelectionContext(transport, profileId, host, HostCategory.OTHER)
                    if (CandidateEngine.isEligible(strategy, ctx)) {
                        return strategy
                    }"""
content = re.sub(pattern1, replacement1, content, count=1)

pattern2 = r"if \(currentStep != null && isFamilyCompatible\(currentStep\.family, transport\) && StrategyExecutionRegistry\.isExecutorSupported\(currentStep, transport\) && \(StrategyStateRepository\.circuitBreakers\[CircuitBreakerKey\(profileId, transport, currentStep\)\] \?: 0L\) < now\) \{[\s\S]*?val hostBlacklistedUntil = StrategyStateRepository\.hostStrategyBlacklist\[blKey\] \?: 0L\n                        if \(hostBlacklistedUntil < now\) \{\n                            return currentStep\n                        \}\n                    \}"
replacement2 = """if (currentStep != null) {
                        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, HostCategory.OTHER)
                        if (CandidateEngine.isEligible(currentStep, ctx)) {
                            return currentStep
                        }
                    }"""
content = re.sub(pattern2, replacement2, content, count=1)

pattern3 = r"if \(isFamilyCompatible\(strategy\.family, transport\) && StrategyExecutionRegistry\.isExecutorSupported\(strategy, transport\) && \(StrategyStateRepository\.circuitBreakers\[CircuitBreakerKey\(profileId, transport, strategy\)\] \?: 0L\) < now\) \{[\s\S]*?val blacklistedUntil = host\?\.let \{ [\s\S]*?\} \?: 0L\n                    if \(blacklistedUntil < now\) \{\n                        return strategy\n                    \}\n                \}"
replacement3 = """val ctx = CandidateEngine.SelectionContext(transport, profileId, host, HostCategory.OTHER)
                if (CandidateEngine.isEligible(strategy, ctx)) {
                    return strategy
                }"""
content = re.sub(pattern3, replacement3, content, count=1)

pattern4 = r"\?\.(takeIf|filter) \{ isFamilyCompatible\(it\.family, transport\) && StrategyExecutionRegistry\.isExecutorSupported\(it, transport\) \}"
replacement4 = """?.takeIf { CandidateEngine.isEligible(it, CandidateEngine.SelectionContext(transport)) }"""
content = re.sub(pattern4, replacement4, content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "w") as f:
    f.write(content)


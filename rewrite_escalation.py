import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyEscalationMatrix.kt", "r") as f:
    content = f.read()

pattern = r"for \(candidate in candidates\) \{[\s\S]*?if \(!StrategyExecutionRegistry\.isExecutorSupported\(candidate, transport\)\) continue[\s\S]*?val cb = StrategyStateRepository\.circuitBreakers.*? \?: 0L\n            if \(cb >= now\) continue"
replacement = """val ctx = CandidateEngine.SelectionContext(transport, profileId, host, HostCategory.OTHER)
        for (candidate in candidates) {
            if (candidate == failedStrategy) continue
            if (!CandidateEngine.isEligible(candidate, ctx)) continue"""

content = re.sub(pattern, replacement, content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyEscalationMatrix.kt", "w") as f:
    f.write(content)


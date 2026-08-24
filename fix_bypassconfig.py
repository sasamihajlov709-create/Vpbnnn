import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    content = f.read()

pattern = r"if \(DpiStrategySelector\.isFamilyCompatible\(base\.family, transport\) &&\n                StrategyExecutionRegistry\.isExecutorSupported\(base, transport\) &&\n                \(StrategyStateRepository\.circuitBreakers\[CircuitBreakerKey.*? \?: 0L\) < now\) \{"
replacement = """val ctx = CandidateEngine.SelectionContext(transport)
            if (CandidateEngine.isEligible(base, ctx)) {"""

content = re.sub(pattern, replacement, content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(content)


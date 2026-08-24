import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "r") as f:
    content = f.read()

pattern = r"val candidates = BypassStrategy\.entries\.filter \{[\s\S]*?StrategyExecutionRegistry\.isExecutorSupported\(it, transport\)\n        \}"
replacement = """val ctx = CandidateEngine.SelectionContext(transport, profileId, null, category)
        val candidates = CandidateEngine.getEligibleCandidates(ctx)"""

content = re.sub(pattern, replacement, content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "w") as f:
    f.write(content)


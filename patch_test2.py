import re

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/PerFlowStrategyIsolationTest.kt", "r") as f:
    content = f.read()

replacement = """
            val state = StrategyStateRepository.getStrategyState(BypassStrategy.TCP_REORDER, transport, HostCategory.OTHER, profileId)
            state.verifiedSuccessCount.incrementAndGet()
            state.weightedSuccess.set(1000000000L) // Massive success weight
            state.score.set(1000000) 
"""
content = re.sub(
    r'            val state = StrategyStateRepository\.getStrategyState\(BypassStrategy\.TCP_REORDER, transport, HostCategory\.OTHER, profileId\)\n            state\.verifiedSuccessCount\.incrementAndGet\(\)\n            state\.score\.set\(1000000\) // Force extremely high score',
    replacement.lstrip('\n'),
    content
)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/PerFlowStrategyIsolationTest.kt", "w") as f:
    f.write(content)

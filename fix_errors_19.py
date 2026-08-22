import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'r') as f:
    analyzer = f.read()

# Replace DpiEngine legacy maps accesses in DpiAnalyzer.
# DpiAnalyzer still tries to read DpiEngine.successHistory and DpiEngine.failureHistory

analyzer = re.sub(r'val totalSuccess = DpiEngine\.successHistory\.values\.sumOf \{ it\.get\(\) \}', r'val totalSuccess = StrategyStateRepository.getAllContextStates().values.sumOf { it.successCount.get() }', analyzer)
analyzer = re.sub(r'val totalFailure = DpiEngine\.failureHistory\.values\.sumOf \{ it\.get\(\) \}', r'val totalFailure = StrategyStateRepository.getAllContextStates().values.sumOf { it.failureCount.get() }', analyzer)

analyzer = re.sub(r'DpiEngine\.strategyScores\.values\.forEach \{ catScores ->.*?\}\s*\}', r'', analyzer, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'w') as f:
    f.write(analyzer)


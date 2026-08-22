import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'r') as f:
    analyzer = f.read()

analyzer = re.sub(r'DpiEngine\.hostStrategyBlacklist', r'StrategyStateRepository.hostStrategyBlacklist', analyzer)
analyzer = re.sub(r'DpiEngine\.consecutiveFailuresByHost', r'StrategyStateRepository.consecutiveFailuresByHost', analyzer)
analyzer = re.sub(r'DpiEngine\.hostSpecificMemory', r'StrategyStateRepository.hostSpecificMemory', analyzer)
analyzer = re.sub(r'DpiEngine\.networkStrategyMemory', r'StrategyStateRepository.networkStrategyMemory', analyzer)

analyzer = re.sub(r'BypassConfig\.frag1 = DpiEngine\.getRecommendedFragSize\(\)', r'// BypassConfig.frag1 = DpiEngine.getRecommendedFragSize()', analyzer)
analyzer = re.sub(r'BypassConfig\.delay1 = DpiEngine\.getRecommendedDelay\(\)', r'// BypassConfig.delay1 = DpiEngine.getRecommendedDelay()', analyzer)
analyzer = re.sub(r'DpiEngine\.pruneStrategies\(\)', r'// DpiEngine.pruneStrategies()', analyzer)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'w') as f:
    f.write(analyzer)


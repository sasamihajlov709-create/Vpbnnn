import re

# Fix DpiAnalyzer.kt
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'r') as f:
    analyzer = f.read()

analyzer = re.sub(r'StrategyStateRepository\.hostStrategyBlacklist', r'DpiEngine.hostStrategyBlacklist', analyzer)
analyzer = re.sub(r'StrategyStateRepository\.consecutiveFailuresByHost', r'DpiEngine.consecutiveFailuresByHost', analyzer)
analyzer = re.sub(r'StrategyStateRepository\.hostSpecificMemory', r'DpiEngine.hostSpecificMemory', analyzer)
analyzer = re.sub(r'StrategyStateRepository\.networkStrategyMemory', r'DpiEngine.networkStrategyMemory', analyzer)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'w') as f:
    f.write(analyzer)


# Fix DpiEngine.kt
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    dpi = f.read()

dpi = re.sub(r'strategyChains\[BypassStrategy\.TCP_SPLIT_2\] = BypassStrategy\.TCP_SPLIT_3', r'// strategyChains[BypassStrategy.TCP_SPLIT_2] = BypassStrategy.TCP_SPLIT_3', dpi)
dpi = re.sub(r'strategyChains\[BypassStrategy\.TCP_SPLIT_3\] = BypassStrategy\.TCP_SPLIT_5', r'// strategyChains[BypassStrategy.TCP_SPLIT_3] = BypassStrategy.TCP_SPLIT_5', dpi)
dpi = re.sub(r'strategyChains\[BypassStrategy\.TLS_SNI_EXT_MANGLE\] = BypassStrategy\.TLS_RECORD_SPLIT', r'// strategyChains[BypassStrategy.TLS_SNI_EXT_MANGLE] = BypassStrategy.TLS_RECORD_SPLIT', dpi)
dpi = re.sub(r'strategyChains\[BypassStrategy\.HTTP_SPACE_MANGLE\] = BypassStrategy\.HTTP_MIXED_CASE', r'// strategyChains[BypassStrategy.HTTP_SPACE_MANGLE] = BypassStrategy.HTTP_MIXED_CASE', dpi)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
    f.write(dpi)


# Fix ProactiveAutoTuner.kt
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'r') as f:
    tuner = f.read()

# I messed up `try { socket.close() }` maybe? Let's check for standalone `t` or `t return` or something like that.
tuner = re.sub(r'\bt\n', r'', tuner) # remove random `t`

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'w') as f:
    f.write(tuner)



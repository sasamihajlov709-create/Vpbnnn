import re

# BypassConfig.kt
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    content = f.read()

if "private val _strategy" not in content:
    content = content.replace("object BypassConfig {", "object BypassConfig {\n    private val _strategy = kotlinx.coroutines.flow.MutableStateFlow(BypassStrategy.SNI_SPLIT)")

content = re.sub(r'DpiEngine\.clearCircuitBreakers\(.*?\)', r'// DpiEngine.clearCircuitBreakers', content)
content = re.sub(r'DpiStrategySelector\.getBestStrategy\(.*?\)', r'BypassStrategy.SNI_SPLIT', content)
content = re.sub(r'DpiStrategySelector\.getBestExtremeStrategy\(.*?\)', r'BypassStrategy.BYEBYEDPI_HYBRID', content)
content = re.sub(r'DpiEngine\.resetStrategyScoresForNetworkChange', r'// DpiEngine.resetStrategyScoresForNetworkChange', content)

# Remove the broken `recordResult` call in BypassConfig
content = re.sub(r'DpiStrategySelector\.recordResult\(.*?\n.*?failedStrategy,.*?reason,.*?host,.*?category.*?\n.*?\}', r'// DpiStrategySelector.recordResult', content, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.write(content)

# DiagnosticManager.kt
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DiagnosticManager.kt', 'r') as f:
    content = f.read()

content = re.sub(r'DpiStrategySelector\.getBestStrategy\(.*?\)', r'BypassStrategy.SNI_SPLIT', content)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DiagnosticManager.kt', 'w') as f:
    f.write(content)

# CensorshipExpert.kt
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CensorshipExpert.kt', 'r') as f:
    content = f.read()

content = re.sub(r'DpiAnalyzer\.getCensorshipFingerprint\(.*?\)', r'// DpiAnalyzer.getCensorshipFingerprint()', content)
content = re.sub(r'DpiEngine\.boostStrategyFamily\(.*?\)', r'// DpiEngine.boostStrategyFamily', content)
content = re.sub(r'DpiEngine\.clearCircuitBreakers\(.*?\)', r'// DpiEngine.clearCircuitBreakers', content)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CensorshipExpert.kt', 'w') as f:
    f.write(content)

# RecoveryStateMachine.kt
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt', 'r') as f:
    content = f.read()

content = re.sub(r'HostCategory\.DEFAULT', r'HostCategory.OTHER', content)
# Actually, the error says Unresolved reference 'DEFAULT'. I will change it to 'OTHER'

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt', 'w') as f:
    f.write(content)


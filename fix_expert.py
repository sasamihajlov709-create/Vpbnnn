import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "r") as f:
    content = f.read()

content = re.sub(
    r"DpiEngine\.circuitBreakers\[([a-zA-Z0-9_\.]+)\]", 
    r"StrategyStateRepository.circuitBreakers[CircuitBreakerKey(profileId, TransportType.TCP, \1)]", 
    content
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyEscalationMatrix.kt", "r") as f:
    content = f.read()

content = re.sub(
    r"DpiEngine\.circuitBreakers\[([a-zA-Z0-9_\.]+)\]", 
    r"StrategyStateRepository.circuitBreakers[CircuitBreakerKey(profileId, transport, \1)]", 
    content
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyEscalationMatrix.kt", "w") as f:
    f.write(content)


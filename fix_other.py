import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    content = f.read()

content = re.sub(
    r"DpiEngine\.circuitBreakers\[([a-zA-Z0-9_\.]+)\]", 
    r"StrategyStateRepository.circuitBreakers[CircuitBreakerKey(NetworkProfileManager.currentProfile.value.id, TransportType.TCP, \1)]", 
    content
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    content = f.read()

content = re.sub(
    r"DpiEngine\.circuitBreakers\[([a-zA-Z0-9_\.]+)\]", 
    r"StrategyStateRepository.circuitBreakers[CircuitBreakerKey(NetworkProfileManager.currentProfile.value.id, transport, \1)]", 
    content
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(content)


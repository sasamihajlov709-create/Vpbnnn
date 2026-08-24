import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    content = f.read()

pattern = r"\(\(StrategyStateRepository\.circuitBreakers\[CircuitBreakerKey.*? \?: 0L\) > System\.currentTimeMillis\(\)\)"
replacement = "!CandidateEngine.isEligible(effectiveStrategy, CandidateEngine.SelectionContext(TransportType.TCP, host = targetHost))"
content = re.sub(pattern, replacement, content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
    f.write(content)


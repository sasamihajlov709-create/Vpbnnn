import os

# 1. Update StrategyState.kt
strategy_state_path = "app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt"
with open(strategy_state_path, "r") as f:
    content = f.read()

circuit_breaker_code = """
data class CircuitBreakerKey(
    val profileId: String,
    val transport: TransportType,
    val strategy: BypassStrategy
)

data class HostFailureKey(
    val profileId: String,
    val host: String
)
"""

if "data class CircuitBreakerKey" not in content:
    content = content.replace("data class StrategyContextKey", circuit_breaker_code + "data class StrategyContextKey")

if "val circuitBreakers = ConcurrentHashMap<CircuitBreakerKey, Long>()" not in content:
    content = content.replace("val consecutiveFailuresByHost = ConcurrentHashMap<String, AtomicInteger>()", 
                              "val consecutiveFailuresByHost = ConcurrentHashMap<HostFailureKey, AtomicInteger>()\n"
                              "    val circuitBreakers = ConcurrentHashMap<CircuitBreakerKey, Long>()\n"
                              "    val consecutiveFailures = ConcurrentHashMap<CircuitBreakerKey, AtomicInteger>()")

if "circuitBreakers.entries.removeIf" not in content:
    content = content.replace("hostStrategyBlacklist.entries.removeIf { it.key.profileId == profileId }",
                              "hostStrategyBlacklist.entries.removeIf { it.key.profileId == profileId }\n"
                              "        circuitBreakers.entries.removeIf { it.key.profileId == profileId }\n"
                              "        consecutiveFailures.entries.removeIf { it.key.profileId == profileId }\n"
                              "        consecutiveFailuresByHost.entries.removeIf { it.key.profileId == profileId }")

with open(strategy_state_path, "w") as f:
    f.write(content)


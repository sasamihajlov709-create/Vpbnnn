import re
with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

old_logic = """                // Network / Local Failures (Ignore or tiny penalty to preserve strategy rating)
                FailureReason.NETWORK_LOST, FailureReason.LOCAL_SOCKET_ERROR -> 0L // 0 weight
                
                FailureReason.UNKNOWN, null -> 200L // Reduced from 800L"""

new_logic = """                // Network / Local Failures (Ignore or tiny penalty to preserve strategy rating)
                FailureReason.NETWORK_LOST, FailureReason.LOCAL_SOCKET_ERROR -> 0L // 0 weight
                
                FailureReason.UNKNOWN, null -> 0L // Zero penalty to protect ratings from local user internet drops"""

content = content.replace(old_logic, new_logic)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(content)

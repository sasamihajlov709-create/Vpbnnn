import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

content = content.replace("contextStates.entries.removeIf { it.key.profileId == profileId && (now - it.value.lastUsedTimestamp.get()) > expiredThreshold }", "contextStates.entries.removeIf { it.key.profileId == profileId && (now - it.value.lastUsedTimestamp.get()) > expiredThreshold }\n    }")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(content)


with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "r") as f:
    content = f.read()

content = content.replace("val average = state.ewmaLatencyMs", "val average = state.ewmaLatencyMs.get()")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt", "w") as f:
    f.write(content)

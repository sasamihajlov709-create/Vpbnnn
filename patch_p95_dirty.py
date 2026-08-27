import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

content = content.replace(
"""                synchronized(recentLatencies) {
                    recentLatencies[latencyIndex] = obs.latencyMs
                    latencyIndex = (latencyIndex + 1) % 100
                    if (latencyCount < 100) latencyCount++
                }""",
"""                synchronized(recentLatencies) {
                    recentLatencies[latencyIndex] = obs.latencyMs
                    latencyIndex = (latencyIndex + 1) % 100
                    if (latencyCount < 100) latencyCount++
                    isP95Dirty = true
                }"""
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(content)


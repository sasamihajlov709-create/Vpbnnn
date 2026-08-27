import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

content = content.replace("val averageLatencyMs: Long", "val ewmaLatencyMs: Long")
content = content.replace("get() = ewmaLatencyMs.get()", "get() = _ewmaLatencyMs.get()")
# Wait, let's see how it's actually defined.

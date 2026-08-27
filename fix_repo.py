import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    lines = f.readlines()

new_lines = []
skip = False
for i, line in enumerate(lines):
    if "val ewmaLatencyMs: Long" in line and "get()" not in line:
        continue
    if "get() = _ewmaLatencyMs.get()" in line:
        continue
    if "get() = ewmaLatencyMs.get()" in line:
        continue
        
with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.writelines(new_lines)

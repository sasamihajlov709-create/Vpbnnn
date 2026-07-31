import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "suspend fun applyBypass" in line:
        print(f"applyBypass at line {i+1}")
    if "when (strategy)" in line:
        print(f"when (strategy) at line {i+1}")

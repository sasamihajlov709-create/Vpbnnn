import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()
import sys

# the compiler error is: 
# e: file:///app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt:2906:41 Syntax error: Unexpected tokens (use ';' to separate expressions on the same line).
lines = text.splitlines()

for i, line in enumerate(lines):
    if line.strip().startswith('BypassStrategy.') and '->' not in line:
         # maybe it was split?
         pass

for i in range(2900, 2920):
    if i < len(lines):
        print(f"{i+1}: {lines[i]}")


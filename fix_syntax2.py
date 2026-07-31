import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

# The error states suspension functions can only be called from coroutine body
# And syntax error near line 2900+
# Let's see what is near line 2906
start = max(0, 2900 - 10)
end = min(len(lines), 2900 + 10)
for i in range(start, end):
    print(f"{i+1}: {lines[i].strip()}")

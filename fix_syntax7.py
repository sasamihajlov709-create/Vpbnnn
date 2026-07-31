import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

# Let's see lines 2900 - 2920 again
for i, line in enumerate(text.splitlines()):
    if 2900 <= i+1 <= 2920:
        print(f"{i+1}: {line}")

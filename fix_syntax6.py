import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

# Fix the duplicate BypassStrategy headers by removing the second one if it's identical
# e.g., "BypassStrategy.TCP_TIMESTAMP_MANGLE -> { BypassStrategy.TCP_TIMESTAMP_MANGLE -> {"
# Wait, let's see how it actually looks in the file near 3080

for i, line in enumerate(text.splitlines()):
    if "TCP_TIMESTAMP_MANGLE" in line:
        print(f"{i+1}: {line}")

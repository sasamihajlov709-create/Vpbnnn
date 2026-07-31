with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

# I want to find ALL "BypassStrategy.[A-Z0-9_]+ BypassStrategy" (missing comma)
import re
matches = re.finditer(r'BypassStrategy\.[A-Z0-9_]+\s+BypassStrategy', text)
for m in matches:
    print(f"Missing comma near index {m.start()}: {m.group(0)}")


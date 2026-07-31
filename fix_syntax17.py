# Check if there are other cases of duplicate/fragmentary strategies
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()
import re
# check for cases like `BypassStrategy.XXX -> { BypassStrategy.YYY -> {`
matches = re.finditer(r'BypassStrategy\.[A-Z0-9_]+\s*->\s*\{\s*BypassStrategy', text)
for m in matches:
    print(f"Malformed case near index {m.start()}: {m.group(0)}")

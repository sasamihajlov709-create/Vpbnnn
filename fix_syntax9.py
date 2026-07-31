with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()
import sys

# Is there another line starting with BypassStrategy that has extra text?
for i, line in enumerate(text.splitlines()):
    if line.strip().startswith("BypassStrategy.") and "->" in line:
        if len(line) > 100 and "BypassStrategy" in line[line.find("->"):]:
            print(f"{i+1}: {line.strip()}")


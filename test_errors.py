with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

import re
matches = re.finditer(r'BypassStrategy\.[A-Z0-9_]+ -> \{', text)
for m in matches:
    start = max(0, m.start() - 20)
    end = min(len(text), m.end() + 20)
    #print(text[start:end])

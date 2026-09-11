with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()
import re
text = re.sub(r'Pair\(strategy, Pair\(baseUtility, telemetry\)\)\s*\}', 'Pair(strategy, Pair(baseUtility, telemetry))\n        }', text)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write(text)

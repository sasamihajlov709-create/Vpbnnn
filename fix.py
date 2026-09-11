with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()

# Fix the brace for transportHealth
import re
text = re.sub(r'            if \(transportHealth < 0\.2\) \{\s*beta \+= 50\.0 \* \(0\.2 - transportHealth\)\s*// Level 2', '            if (transportHealth < 0.2) {\n                beta += 50.0 * (0.2 - transportHealth)\n            }\n            \n            // Level 2', text)

# Fix the brace for hostMemory
text = re.sub(r'            if \(hostMemory != null && hostMemory\.strategy == strategy && hostMemory\.successCount > 0 && hostMemory\.failureCount == 0\) \{\s*val hostDecay = Math\.max\(0\.1, 1\.0 - \(System\.currentTimeMillis\(\) - hostMemory\.timestamp\) / \(24\.0 \* 3600\.0 \* 1000\.0\)\)\s*val boost = Math\.min\(50\.0, hostMemory\.successCount \* hostMemory\.confidence \* 5\.0\) \* hostDecay\s*alpha \+= boost\s*// STABLE mode', '            if (hostMemory != null && hostMemory.strategy == strategy && hostMemory.successCount > 0 && hostMemory.failureCount == 0) {\n                val hostDecay = Math.max(0.1, 1.0 - (System.currentTimeMillis() - hostMemory.timestamp) / (24.0 * 3600.0 * 1000.0))\n                val boost = Math.min(50.0, hostMemory.successCount * hostMemory.confidence * 5.0) * hostDecay\n                alpha += boost\n            }\n\n            // STABLE mode', text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write(text)

import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "r") as f:
    text = f.read()

replacement = """            // Level 1: Apply Host Memory bonus if the strategy matches the known best host strategy
            if (hostMemory != null && hostMemory.strategy == strategy && hostMemory.successCount > 0) {
                val decay = Math.max(0.1, 1.0 - (System.currentTimeMillis() - hostMemory.timestamp) / (24.0 * 3600.0 * 1000.0))
                val boost = Math.min(50.0, hostMemory.successCount * hostMemory.confidence * 5.0) * decay
                alpha += boost
            }"""

text = re.sub(r'            // Level 1: Apply Host Memory bonus if the strategy matches the known best host strategy\n            if \(hostMemory != null && hostMemory\.strategy == strategy && hostMemory\.successCount > 0\) \{\n                // Boost alpha proportionally to confidence and success count\n                alpha \+= \(hostMemory\.successCount \* hostMemory\.confidence \* 20\.0\) \n            \}', replacement, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "w") as f:
    f.write(text)

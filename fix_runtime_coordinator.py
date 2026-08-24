import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "r") as f:
    content = f.read()

pattern = r"val best = candidates\.maxByOrNull \{ strategy ->[\s\S]*?\} \?: fallback"
replacement = """val ranked = CandidateEngine.rankCandidatesBayesian(candidates, ctx)
        val best = ranked.firstOrNull() ?: fallback"""

content = re.sub(pattern, replacement, content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "w") as f:
    f.write(content)


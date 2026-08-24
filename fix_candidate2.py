import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "r") as f:
    content = f.read()

content = content.replace("if (isPanic && strategy.group == StrategyGroup.LIGHT || strategy.group == StrategyGroup.MEDIUM) return false", "if (isPanic && (strategy.group == StrategyGroup.LIGHT || strategy.group == StrategyGroup.MEDIUM)) return false")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "w") as f:
    f.write(content)


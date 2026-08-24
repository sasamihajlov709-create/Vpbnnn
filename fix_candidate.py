import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "r") as f:
    content = f.read()

content = content.replace("strategy.group == StrategyGroup.BASIC", "strategy.group == StrategyGroup.LIGHT || strategy.group == StrategyGroup.MEDIUM")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "w") as f:
    f.write(content)


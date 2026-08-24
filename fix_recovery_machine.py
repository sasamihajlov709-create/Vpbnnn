import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "r") as f:
    content = f.read()

pattern1 = r"\.filter \{ StrategyExecutionRegistry\.isExecutorSupported\(it, (.*?)\) \}\n                val selected = candidates\.maxWithOrNull\([\s\S]*?\)\.thenBy \{ it\.name\.hashCode\(\) \}\n                \) \?: (.*?)\n"
replacement1 = r""".let { baseList -> 
                    val ctx = CandidateEngine.SelectionContext(\1, profileId, null, category)
                    val eligible = CandidateEngine.getEligibleCandidates(ctx, baseList)
                    CandidateEngine.rankCandidatesBayesian(eligible, ctx).firstOrNull() ?: \2
                }
"""

content = re.sub(pattern1, replacement1, content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "w") as f:
    f.write(content)


with open('app/src/test/java/com/aistudio/pinkproxy/fresh/CandidateEngineTest.kt', 'r') as f:
    text = f.read()

rep = """
        val candidates = listOf(strategyGood, strategyBad)
        var goodWins = 0
        val runs = 1000
        for (i in 0 until runs) {
            val ranked = CandidateEngine.rankCandidatesBayesian(candidates, ctx)
            if (ranked.first() == strategyGood) {
                goodWins++
            }
        }
        
        assertTrue("Good strategy should win significantly more often (won $goodWins/$runs)", goodWins > 900)
"""

import re
text = re.sub(r'        val candidates = listOf\(strategyGood, strategyBad\).*?assertNotNull\(ranked\.first\(\)\)', rep.strip(), text, flags=re.DOTALL)

with open('app/src/test/java/com/aistudio/pinkproxy/fresh/CandidateEngineTest.kt', 'w') as f:
    f.write(text)

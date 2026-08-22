import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'r') as f:
    content = f.read()

replacement = """    fun checkGlobalStall() {
        val states = StrategyStateRepository.getAllContextStates().values
        val totalSuccess = states.sumOf { it.successCount.get() }
        val totalFailure = states.sumOf { it.failureCount.get() }
        val total = totalSuccess + totalFailure
        if (total > 20) {
            val rate = (totalSuccess.toDouble() / total * 100)
            val fingerprint = getCensorshipFingerprint()
            val decision = DpiPolicyEngine.evaluatePolicy(fingerprint, rate, total)
            if (decision.shouldEnterPanic || decision.shouldReset) {
                DpiPolicyEngine.applyPolicyDecision(decision)
            }
        }
    }"""

content = re.sub(r'    fun checkGlobalStall\(\) \{.*?(?=\n\n|\n\})', replacement, content, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'w') as f:
    f.write(content)

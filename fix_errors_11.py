import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'r') as f:
    content = f.read()

replacement = """        if (totalSuccess + totalFailure > 1000) {
            val states = StrategyStateRepository.getAllContextStates().values
            states.forEach { state ->
                state.successCount.updateAndGet { (it * 0.5).toInt() }
                state.failureCount.updateAndGet { (it * 0.5).toInt() }
                state.weightedSuccess.updateAndGet { (it * 0.5).toLong() }
            }
        }"""
content = re.sub(r'        if \(totalSuccess \+ totalFailure > 1000\) \{.*?\}', replacement, content, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'w') as f:
    f.write(content)

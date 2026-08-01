import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    code = f.read()

old_func = """    private fun analyzeAndAdjust() {
        val totalSuccess = successHistory.values.sumOf { it.get() }
        val totalFailure = failureHistory.values.sumOf { it.get() }"""

new_func = """    private fun analyzeAndAdjust() {
        // Cleanup memory
        if (hostStrategyBlacklist.size > 500) {
            val now = System.currentTimeMillis()
            val toRemove = hostStrategyBlacklist.filterValues { map -> map.values.all { it < now } }.keys
            toRemove.forEach { hostStrategyBlacklist.remove(it) }
            if (hostStrategyBlacklist.size > 1000) hostStrategyBlacklist.clear() // Hard reset
        }

        val totalSuccess = successHistory.values.sumOf { it.get() }
        val totalFailure = failureHistory.values.sumOf { it.get() }"""

if old_func in code:
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
        f.write(code.replace(old_func, new_func))
else:
    print("Could not find the block to replace")


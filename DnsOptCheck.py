with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsOptimizer.kt', 'r') as f:
    text = f.read()

import re
matches = re.finditer(r'suspend fun runOptimizationCycle', text)
for m in matches:
    print("Found runOptimizationCycle")

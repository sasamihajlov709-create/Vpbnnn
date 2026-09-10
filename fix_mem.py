import re

with open('app/src/test/java/com/aistudio/pinkproxy/fresh/CandidateEngineTest.kt', 'r') as f:
    text = f.read()

replacement = '''
        StrategyStateRepository.contextualHostMemory[key] = HostMemory(
            strategy = strategyMem,
            timestamp = System.currentTimeMillis(),
            successCount = 5,
            transport = TransportType.TCP,
            profileId = "DEFAULT"
        )
'''

text = re.sub(r'StrategyStateRepository\.contextualHostMemory\[key\] = HostMemory\([^)]+\)', replacement.strip(), text, flags=re.DOTALL)

with open('app/src/test/java/com/aistudio/pinkproxy/fresh/CandidateEngineTest.kt', 'w') as f:
    f.write(text)

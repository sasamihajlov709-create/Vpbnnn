with open("app/src/test/java/com/aistudio/pinkproxy/fresh/RecoveryHostContextTest.kt", "r") as f:
    content = f.read()

# Fix Unresolved reference 'clearAll'
content = content.replace("StrategyStateRepository.clearAll()", "StrategyStateRepository.circuitBreakers.clear()\n        StrategyStateRepository.hostStrategyBlacklist.clear()")

# Fix No value passed for parameter 'transport' and 'profileId' in HostMemory
old_memory = """val memory = HostMemory(
            strategy = expectedStrategy,
            successCount = 5,
            confidence = 1.0,
            timestamp = System.currentTimeMillis()
        )"""

new_memory = """val memory = HostMemory(
            strategy = expectedStrategy,
            transport = transport,
            profileId = profileId,
            successCount = 5,
            confidence = 1.0,
            timestamp = System.currentTimeMillis()
        )"""

content = content.replace(old_memory, new_memory)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/RecoveryHostContextTest.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    code = f.read()

new_func = """    fun resetProfile(profileId: String) {
        contextStates.entries.removeIf { it.key.profileId == profileId }
        networkStrategyMemory.remove(profileId)
        contextualHostMemory.entries.removeIf { it.key.profileId == profileId }
        hostStrategyBlacklist.entries.removeIf { it.key.profileId == profileId }
    }"""

code = code.replace("    fun resetAll() {\n        contextStates.clear()\n        networkStrategyMemory.clear()\n        contextualHostMemory.clear()\n        consecutiveFailuresByHost.clear()\n        hostStrategyBlacklist.clear()\n    }", new_func)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(code)

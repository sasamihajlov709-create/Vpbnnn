import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

replacement = """
    fun resetProfile(profileId: String) {
        contextStates.entries.removeIf { it.key.profileId == profileId }
        networkStrategyMemory.remove(profileId)
        contextualHostMemory.entries.removeIf { it.key.profileId == profileId }
        hostStrategyBlacklist.entries.removeIf { it.key.profileId == profileId }
        circuitBreakers.entries.removeIf { it.key.profileId == profileId }
        consecutiveFailures.entries.removeIf { it.key.profileId == profileId }
        consecutiveFailuresByHost.entries.removeIf { it.key.profileId == profileId }
        DpiEngine.eventHistory.entries.removeIf { it.key.profileId == profileId }
    }
"""

content = re.sub(
    r'    fun resetProfile\(profileId: String\)\s*\{[^}]+\}',
    replacement.lstrip('\n'),
    content
)

replacement_clear = """
    fun clearProfileState(profileId: String) {
        contextStates.entries.removeIf { it.key.profileId == profileId }
        networkStrategyMemory.remove(profileId)
        contextualHostMemory.entries.removeIf { it.key.profileId == profileId }
        hostStrategyBlacklist.entries.removeIf { it.key.profileId == profileId }
        circuitBreakers.entries.removeIf { it.key.profileId == profileId }
        consecutiveFailures.entries.removeIf { it.key.profileId == profileId }
        consecutiveFailuresByHost.entries.removeIf { it.key.profileId == profileId }
        DpiEngine.eventHistory.entries.removeIf { it.key.profileId == profileId }
    }
"""

content = re.sub(
    r'    fun clearProfileState\(profileId: String\)\s*\{[^}]+\}',
    replacement_clear.lstrip('\n'),
    content
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(content)


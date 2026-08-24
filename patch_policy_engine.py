with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "r") as f:
    code = f.read()

new_func = """    fun resetProfileEngineStates(profileId: String) {
        Log.w("DpiPolicyEngine", "Executing state reset for profile $profileId due to critical network anomaly policy trigger.")
        StrategyStateRepository.resetProfile(profileId)
        // DpiEngine maps usually use strategy as key, so it might need some other clearance, but clear() affects everything.
        // For now let's just clear for the specific strategy if possible, or clear circuit breakers since they are transient anyway.
        DpiEngine.circuitBreakers.clear()
        DpiEngine.consecutiveFailures.clear()
    }"""

code = code.replace("    fun resetAllEngineStates() {\n        Log.w(\"DpiPolicyEngine\", \"Executing full state reset due to critical network anomaly policy trigger.\")\n        StrategyStateRepository.resetAll()\n        DpiEngine.circuitBreakers.clear()\n        DpiEngine.consecutiveFailures.clear()\n    }", new_func)

code = code.replace("resetAllEngineStates()", "resetProfileEngineStates(NetworkProfileManager.currentProfile.value.id)")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "w") as f:
    f.write(code)

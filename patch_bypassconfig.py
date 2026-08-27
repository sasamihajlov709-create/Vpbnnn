import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    text = f.read()

replacement = """    fun getBestStrategyForHost(host: String?, transport: TransportType): BypassStrategy {
        if (host != null) {
            val profileId = NetworkProfileManager.currentProfile.value.id
            val override = FlowStrategyOverrideStore.getOverride(host, transport, profileId)
            if (override != null) {
                return override
            }
        }
        
        val now = System.currentTimeMillis()"""

text = text.replace("    fun getBestStrategyForHost(host: String?, transport: TransportType): BypassStrategy {\n        val now = System.currentTimeMillis()", replacement)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(text)

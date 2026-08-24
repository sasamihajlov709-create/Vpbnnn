sed -i '/fun getAllContextStates/i \
    fun getStates(\
        profileId: String? = null,\
        transport: TransportType? = null,\
        category: HostCategory? = null,\
        strategy: BypassStrategy? = null\
    ): List<StrategyState> {\
        return contextStates.entries.mapNotNull { (key, state) ->\
            if (profileId != null && key.profileId != profileId) return@mapNotNull null\
            if (transport != null && key.transport != transport) return@mapNotNull null\
            if (category != null && key.category != category) return@mapNotNull null\
            if (strategy != null && key.strategy != strategy) return@mapNotNull null\
            state\
        }\
    }\
' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt

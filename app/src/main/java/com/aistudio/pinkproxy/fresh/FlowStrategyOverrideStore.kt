package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ConcurrentHashMap

data class FlowStrategyOverrideKey(
    val host: String,
    val transport: TransportType,
    val profileId: String
)

data class FlowStrategyOverride(
    val strategy: BypassStrategy,
    val expiresAt: Long,
    val reason: String
)

object FlowStrategyOverrideStore {
    private val overrides = ConcurrentHashMap<FlowStrategyOverrideKey, FlowStrategyOverride>()
    private const val DEFAULT_OVERRIDE_TTL_MS = 5 * 60 * 1000L // 5 minutes

    fun putOverride(
        host: String,
        transport: TransportType,
        profileId: String,
        strategy: BypassStrategy,
        reason: String,
        ttlMs: Long = DEFAULT_OVERRIDE_TTL_MS
    ) {
        val key = FlowStrategyOverrideKey(host, transport, profileId)
        val expiresAt = System.currentTimeMillis() + ttlMs
        overrides[key] = FlowStrategyOverride(strategy, expiresAt, reason)
    }

    fun getOverride(
        host: String,
        transport: TransportType,
        profileId: String
    ): BypassStrategy? {
        val key = FlowStrategyOverrideKey(host, transport, profileId)
        val override = overrides[key] ?: return null
        
        if (System.currentTimeMillis() > override.expiresAt) {
            overrides.remove(key)
            return null
        }
        
        return override.strategy
    }

    fun clearOverridesForProfile(profileId: String) {
        overrides.entries.removeIf { it.key.profileId == profileId }
    }
    
    fun clearAll() {
        overrides.clear()
    }
}

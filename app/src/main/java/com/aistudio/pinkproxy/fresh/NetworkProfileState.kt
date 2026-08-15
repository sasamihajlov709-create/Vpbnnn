package com.aistudio.pinkproxy.fresh

/**
 * Encapsulated immutable snapshot of learned DPI bypass metrics for a single network profile.
 */
data class NetworkProfileState(
    val profileId: String,
    val scores: Map<HostCategory, Map<BypassStrategy, Int>> = emptyMap(),
    val categorySuccess: Map<HostCategory, Map<BypassStrategy, Int>> = emptyMap(),
    val categoryFailure: Map<HostCategory, Map<BypassStrategy, Int>> = emptyMap(),
    val networkMemory: Map<HostCategory, DpiEngine.NetworkMemory> = emptyMap(),
    val hostMemory: Map<String, DpiEngine.HostMemory> = emptyMap(),
    val hostBlacklist: Map<String, Map<BypassStrategy, Long>> = emptyMap(),
    val lastUpdated: Long = System.currentTimeMillis()
)

package com.aistudio.pinkproxy.fresh

/**
 * Encapsulated immutable snapshot of learned DPI bypass metrics for a single network profile.
 */
data class NetworkProfileState(
    val profileId: String,
    val scores: Map<HostCategory, Map<BypassStrategy, Int>> = emptyMap(),
    val categorySuccess: Map<HostCategory, Map<BypassStrategy, Int>> = emptyMap(),
    val categoryFailure: Map<HostCategory, Map<BypassStrategy, Int>> = emptyMap(),
    val categoryWeightedSuccess: Map<HostCategory, Map<BypassStrategy, Long>> = emptyMap(),
    val weightedSuccess: Map<BypassStrategy, Long> = emptyMap(),
    val networkMemory: Map<HostCategory, NetworkMemory> = emptyMap(),
    val hostMemory: Map<String, HostMemory> = emptyMap(),
    val hostBlacklist: Map<String, Map<BypassStrategy, Long>> = emptyMap(),
    val lastUpdated: Long = System.currentTimeMillis()
)

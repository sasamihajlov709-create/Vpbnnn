package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

object DpiStorage {

    fun captureStrategyProfileState(profileId: String): StrategyProfileState {
        val netMem = (StrategyStateRepository.networkStrategyMemory[profileId] ?: emptyMap()).toMap()

        val ctxHostMem = StrategyStateRepository.contextualHostMemory.filterKeys { it.profileId == profileId }.toMap()

        val hostBl = mutableListOf<HostBlacklistEntry>()
        StrategyStateRepository.hostStrategyBlacklist.forEach { (key, until) ->
            if (key.profileId == profileId) {
                hostBl.add(HostBlacklistEntry(key.host, key.transport, key.strategy, until))
            }
        }

        val ctxStates = mutableMapOf<StrategyContextKey, StrategyMetricState>()
        StrategyStateRepository.getAllContextStates().forEach { (key, state) ->
            if (key.profileId == profileId) {
                ctxStates[key] = StrategyMetricState(
                    score = state.score.get(),
                    successCount = state.successCount.get(),
                    failureCount = state.failureCount.get(),
                    weightedSuccess = state.weightedSuccess.get(),
                    verifiedSuccessCount = state.verifiedSuccessCount.get(),
                    totalLatencyMs = state.ewmaLatencyMs.get(),
                    lastUsedTimestamp = state.lastUsedTimestamp.get()
                )
            }
        }

        return StrategyProfileState(
            version = 3,
            profileId = profileId,
            timestamp = System.currentTimeMillis(),
            networkMemory = netMem,
            contextualHostMemory = ctxHostMem,
            hostBlacklist = hostBl,
            contextualStrategyStates = ctxStates
        )
    }

    fun restoreStrategyProfileState(state: StrategyProfileState) {
        StrategyStateRepository.clearProfileState(state.profileId)
        StrategyStateRepository.restoreStates(state.contextualStrategyStates)

        val netMap = StrategyStateRepository.networkStrategyMemory.getOrPut(state.profileId) { ConcurrentHashMap() }
        netMap.clear()
        netMap.putAll(state.networkMemory)

        state.contextualHostMemory.forEach { (key, mem) ->
            StrategyStateRepository.contextualHostMemory[key] = mem
        }

        state.hostBlacklist.forEach { entry ->
            val key = HostStrategyBlacklistKey(entry.host, entry.transport, state.profileId, entry.strategy)
            StrategyStateRepository.hostStrategyBlacklist[key] = entry.until
        }
    }

    fun saveProfileScores(context: Context, profileId: String) {
        val state = captureStrategyProfileState(profileId)
        val jsonStr = state.toJson()
        val v2Prefs = context.getSharedPreferences("dpi_profile_v2_$profileId", Context.MODE_PRIVATE)
        v2Prefs.edit().putString("state_json", jsonStr).apply()

        AutoTtlProber.saveTtlMtuState(context, profileId)
        updateProfileRegistry(context, profileId)
    }

    fun loadProfileScores(context: Context, profileId: String) {
        AutoTtlProber.loadTtlMtuState(context, profileId)

        val v2Prefs = context.getSharedPreferences("dpi_profile_v2_$profileId", Context.MODE_PRIVATE)
        val jsonStr = v2Prefs.getString("state_json", null)
        if (!jsonStr.isNullOrBlank()) {
            val state = StrategyProfileState.fromJson(jsonStr)
            if (state != null) {
                restoreStrategyProfileState(state)
                return
            }
        }
    }

    private fun updateProfileRegistry(context: Context, profileId: String) {
        try {
            val registry = context.getSharedPreferences("dpi_profiles_registry", Context.MODE_PRIVATE)
            val editor = registry.edit()
            val now = System.currentTimeMillis()
            editor.putLong("ts_$profileId", now)

            val allProfiles = registry.getStringSet("registered_profiles", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
            allProfiles.add(profileId)

            if (allProfiles.size > 25) {
                val oldest = allProfiles.minByOrNull { id -> registry.getLong("ts_$id", 0L) }
                if (oldest != null && oldest != profileId) {
                    allProfiles.remove(oldest)
                    editor.remove("ts_$oldest")
                    context.getSharedPreferences("dpi_scores_$oldest", Context.MODE_PRIVATE).edit().clear().apply()
                    context.getSharedPreferences("dpi_profile_v2_$oldest", Context.MODE_PRIVATE).edit().clear().apply()
                    context.getSharedPreferences("dpi_host_mem_$oldest", Context.MODE_PRIVATE).edit().clear().apply()
                    context.getSharedPreferences("dpi_host_bl_$oldest", Context.MODE_PRIVATE).edit().clear().apply()
                }
            }
            editor.putStringSet("registered_profiles", allProfiles)
            editor.apply()
        } catch (e: Exception) {
            Log.v("DpiStorage", "Profile registry update error: ${e.message}")
        }
    }
    
    fun loadScores(context: Context) {
        val currentProfile = NetworkProfileManager.currentProfile.value
        loadProfileScores(context, currentProfile.id)
    }
}

package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

object DpiStorage {

    fun captureStrategyProfileState(profileId: String): StrategyProfileState {
        val netMem = (DpiEngine.networkStrategyMemory[profileId] ?: emptyMap()).toMap()

        val ctxHostMem = if (DpiEngine.contextualHostMemory.isNotEmpty()) {
            DpiEngine.contextualHostMemory.toMap()
        } else {
            DpiEngine.hostSpecificMemory.mapKeys { (host, mem) ->
                HostContextKey(host, mem.transport, mem.profileId)
            }
        }

        val hostBl = DpiEngine.hostStrategyBlacklist.mapValues { (_, map) -> map.toMap() }

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
        StrategyStateRepository.restoreStates(state.contextualStrategyStates)

        val netMap = DpiEngine.networkStrategyMemory.getOrPut(state.profileId) { ConcurrentHashMap() }
        netMap.clear()
        netMap.putAll(state.networkMemory)

        DpiEngine.contextualHostMemory.clear()
        DpiEngine.hostSpecificMemory.clear()
        state.contextualHostMemory.forEach { (key, mem) ->
            DpiEngine.contextualHostMemory[key] = mem
            DpiEngine.hostSpecificMemory[key.host] = mem
        }

        DpiEngine.hostStrategyBlacklist.clear()
        state.hostBlacklist.forEach { (host, map) ->
            val concMap = ConcurrentHashMap<BypassStrategy, Long>()
            concMap.putAll(map)
            DpiEngine.hostStrategyBlacklist[host] = concMap
        }
    }

    fun saveProfileScores(context: Context, profileId: String) {
        val state = captureStrategyProfileState(profileId)
        val jsonStr = state.toJson()
        val v2Prefs = context.getSharedPreferences("dpi_profile_v2_$profileId", Context.MODE_PRIVATE)
        v2Prefs.edit().putString("state_json", jsonStr).apply()

        saveHostMemoryForProfile(context, profileId, isSynchronous = false)
        AutoTtlProber.saveTtlMtuState(context, profileId)
        updateProfileRegistry(context, profileId)
    }

    fun loadProfileScores(context: Context, profileId: String) {
        loadHostMemoryForProfile(context, profileId)
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

    private fun saveHostMemoryForProfile(context: Context, profileId: String, isSynchronous: Boolean = false) {
        val prefs = context.getSharedPreferences("dpi_host_mem_$profileId", Context.MODE_PRIVATE)
        val editor = prefs.edit()
        editor.clear()
        val now = System.currentTimeMillis()
        val expiry = 86400000L * 7

        DpiEngine.hostSpecificMemory.forEach { (host, mem) ->
            if (now - mem.timestamp < expiry) {
                editor.putString(host, "${mem.strategy.name}|${mem.timestamp}|${mem.successCount}")
            }
        }
        if (isSynchronous) editor.commit() else editor.apply()

        val blPrefs = context.getSharedPreferences("dpi_host_bl_$profileId", Context.MODE_PRIVATE)
        val blEditor = blPrefs.edit()
        blEditor.clear()

        DpiEngine.hostStrategyBlacklist.forEach { (host, map) ->
            val validEntries = map.filter { it.value > now }.map { "${it.key.name}:${it.value}" }.joinToString(",")
            if (validEntries.isNotEmpty()) {
                blEditor.putString(host, validEntries)
            }
        }
        if (isSynchronous) blEditor.commit() else blEditor.apply()
    }

    private fun loadHostMemoryForProfile(context: Context, profileId: String) {
        DpiEngine.hostSpecificMemory.clear()
        DpiEngine.hostStrategyBlacklist.clear()

        val prefs = context.getSharedPreferences("dpi_host_mem_$profileId", Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val expiry = 86400000L * 7

        prefs.all.forEach { (host, value) ->
            if (value is String) {
                val parts = value.split("|")
                if (parts.size >= 2) {
                    try {
                        val strategy = BypassStrategy.valueOf(parts[0])
                        val ts = parts[1].toLong()
                        val successCount = if (parts.size >= 3) parts[2].toIntOrNull() ?: 1 else 1
                        if (now - ts < expiry) {
                            DpiEngine.hostSpecificMemory[host] = DpiEngine.HostMemory(strategy, ts, successCount)
                        }
                    } catch (e: Throwable) {}
                }
            }
        }

        val blPrefs = context.getSharedPreferences("dpi_host_bl_$profileId", Context.MODE_PRIVATE)
        blPrefs.all.forEach { (host, value) ->
            if (value is String) {
                val map = DpiEngine.hostStrategyBlacklist.getOrPut(host) { ConcurrentHashMap() }
                value.split(",").forEach { entry ->
                    val parts = entry.split(":")
                    if (parts.size == 2) {
                        try {
                            val strategy = BypassStrategy.valueOf(parts[0])
                            val until = parts[1].toLong()
                            if (until > now) {
                                map[strategy] = until
                            }
                        } catch (e: Throwable) {}
                    }
                }
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

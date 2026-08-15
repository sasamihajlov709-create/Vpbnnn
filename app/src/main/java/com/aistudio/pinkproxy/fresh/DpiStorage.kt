package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

object DpiStorage {

    fun captureProfileState(profileId: String): NetworkProfileState {
        val scores = DpiEngine.strategyScores.mapValues { (_, map) ->
            map.mapValues { (_, atomic) -> atomic.get() }
        }
        val catSuccess = DpiEngine.categorySuccessHistory.mapValues { (_, map) ->
            map.mapValues { (_, atomic) -> atomic.get() }
        }
        val catFailure = DpiEngine.categoryFailureHistory.mapValues { (_, map) ->
            map.mapValues { (_, atomic) -> atomic.get() }
        }
        val catWeightedSuccess = DpiEngine.categoryWeightedSuccessHistory.mapValues { (_, map) ->
            map.mapValues { (_, atomic) -> atomic.get() }
        }
        val weightedSuccess = DpiEngine.weightedSuccessHistory.mapValues { (_, atomic) -> atomic.get() }
        val netMem = (DpiEngine.networkStrategyMemory[profileId] ?: emptyMap()).toMap()
        val hostMem = DpiEngine.hostSpecificMemory.toMap()
        val hostBl = DpiEngine.hostStrategyBlacklist.mapValues { (_, map) -> map.toMap() }

        return NetworkProfileState(
            profileId = profileId,
            scores = scores,
            categorySuccess = catSuccess,
            categoryFailure = catFailure,
            categoryWeightedSuccess = catWeightedSuccess,
            weightedSuccess = weightedSuccess,
            networkMemory = netMem,
            hostMemory = hostMem,
            hostBlacklist = hostBl,
            lastUpdated = System.currentTimeMillis()
        )
    }

    fun restoreProfileState(state: NetworkProfileState) {
        DpiEngine.strategyScores.forEach { (cat, map) ->
            val catScores = state.scores[cat]
            map.forEach { (strat, atomic) ->
                atomic.set(catScores?.get(strat) ?: 100)
            }
        }
        DpiEngine.categorySuccessHistory.forEach { (cat, map) ->
            val catMap = state.categorySuccess[cat]
            map.forEach { (strat, atomic) ->
                atomic.set(catMap?.get(strat) ?: 0)
            }
        }
        DpiEngine.categoryFailureHistory.forEach { (cat, map) ->
            val catMap = state.categoryFailure[cat]
            map.forEach { (strat, atomic) ->
                atomic.set(catMap?.get(strat) ?: 0)
            }
        }
        DpiEngine.categoryWeightedSuccessHistory.forEach { (cat, map) ->
            val catMap = state.categoryWeightedSuccess[cat]
            map.forEach { (strat, atomic) ->
                atomic.set(catMap?.get(strat) ?: 0L)
            }
        }
        DpiEngine.weightedSuccessHistory.forEach { (strat, atomic) ->
            atomic.set(state.weightedSuccess[strat] ?: 0L)
        }
        DpiEngine.networkStrategyMemory.clear()
        if (state.networkMemory.isNotEmpty()) {
            val catMap = ConcurrentHashMap(state.networkMemory)
            DpiEngine.networkStrategyMemory[state.profileId] = catMap
        }
        DpiEngine.hostSpecificMemory.clear()
        DpiEngine.hostSpecificMemory.putAll(state.hostMemory)
        DpiEngine.hostStrategyBlacklist.clear()
        state.hostBlacklist.forEach { (host, map) ->
            DpiEngine.hostStrategyBlacklist[host] = ConcurrentHashMap(map)
        }
    }

    fun saveScores(context: Context, synchronous: Boolean = false) {
        val profileId = NetworkProfileManager.currentProfile.value.id
        saveProfileScores(context, profileId, synchronous)
    }

    fun loadScores(context: Context) {
        val profileId = NetworkProfileManager.currentProfile.value.id
        loadProfileScores(context, profileId)
    }

    fun saveProfileScores(context: Context, profileId: String, synchronous: Boolean = false) {
        saveHostMemoryForProfile(context, profileId, synchronous)
        AutoTtlProber.saveTtlMtuState(context, profileId)
        val prefs = context.getSharedPreferences("dpi_scores_$profileId", Context.MODE_PRIVATE)
        val editor = prefs.edit()
        editor.clear()
        DpiEngine.strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                editor.putInt("${cat.name}_${strat.name}", score.get())
            }
        }
        DpiEngine.categorySuccessHistory.forEach { (cat, map) ->
            map.forEach { (strat, cnt) ->
                editor.putInt("succ_${cat.name}_${strat.name}", cnt.get())
            }
        }
        DpiEngine.categoryFailureHistory.forEach { (cat, map) ->
            map.forEach { (strat, cnt) ->
                editor.putInt("fail_${cat.name}_${strat.name}", cnt.get())
            }
        }
        DpiEngine.categoryWeightedSuccessHistory.forEach { (cat, map) ->
            map.forEach { (strat, cnt) ->
                editor.putLong("wsucc_${cat.name}_${strat.name}", cnt.get())
            }
        }
        DpiEngine.weightedSuccessHistory.forEach { (strat, cnt) ->
            editor.putLong("wsucc_global_${strat.name}", cnt.get())
        }
        // Save network strategy memory strictly for this profile
        val profileMem = DpiEngine.networkStrategyMemory[profileId]
        if (profileMem != null) {
            profileMem.forEach { (cat, mem) ->
                editor.putString("netmem_${profileId}::${cat.name}", "${mem.strategy.name}|${mem.timestamp}|${mem.confidence}")
            }
        }
        if (synchronous) editor.commit() else editor.apply()

        // Also update registry of known profiles
        updateProfileRegistry(context, profileId)
    }

    fun loadProfileScores(context: Context, profileId: String) {
        loadHostMemoryForProfile(context, profileId)
        AutoTtlProber.loadTtlMtuState(context, profileId)
        val prefs = context.getSharedPreferences("dpi_scores_$profileId", Context.MODE_PRIVATE)
        
        // If profile prefs are empty, fallback to legacy/default scores
        val hasSavedScores = prefs.all.isNotEmpty()
        val sourcePrefs = if (hasSavedScores) prefs else context.getSharedPreferences("dpi_engine_scores", Context.MODE_PRIVATE)

        DpiEngine.strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                val saved = sourcePrefs.getInt("${cat.name}_${strat.name}", -1)
                if (saved != -1) score.set(saved) else score.set(100)
            }
        }

        DpiEngine.categorySuccessHistory.forEach { (cat, map) ->
            map.forEach { (strat, cnt) ->
                val saved = sourcePrefs.getInt("succ_${cat.name}_${strat.name}", 0)
                cnt.set(saved)
            }
        }
        DpiEngine.categoryFailureHistory.forEach { (cat, map) ->
            map.forEach { (strat, cnt) ->
                val saved = sourcePrefs.getInt("fail_${cat.name}_${strat.name}", 0)
                cnt.set(saved)
            }
        }

        DpiEngine.categoryWeightedSuccessHistory.forEach { (cat, map) ->
            map.forEach { (strat, cnt) ->
                val saved = sourcePrefs.getLong("wsucc_${cat.name}_${strat.name}", 0L)
                cnt.set(saved)
            }
        }
        DpiEngine.weightedSuccessHistory.forEach { (strat, cnt) ->
            val saved = sourcePrefs.getLong("wsucc_global_${strat.name}", 0L)
            cnt.set(saved)
        }

        DpiEngine.networkStrategyMemory.clear()
        sourcePrefs.all.keys.filter { it.startsWith("netmem_") }.forEach { key ->
            val raw = key.removePrefix("netmem_")
            val parts = if (raw.contains("::")) raw.split("::", limit = 2) else raw.split("_", limit = 2)
            if (parts.size == 2) {
                val netType = parts[0]
                val catName = parts[1]
                val valStr = sourcePrefs.getString(key, null)
                if (valStr != null) {
                    try {
                        val cat = HostCategory.valueOf(catName)
                        val valParts = valStr.split("|")
                        val strat = BypassStrategy.valueOf(valParts[0])
                        val ts = if (valParts.size > 1) valParts[1].toLongOrNull() ?: System.currentTimeMillis() else System.currentTimeMillis()
                        val conf = if (valParts.size > 2) valParts[2].toDoubleOrNull() ?: 1.0 else 1.0
                        val catMap = DpiEngine.networkStrategyMemory.getOrPut(netType) { ConcurrentHashMap() }
                        catMap[cat] = DpiEngine.NetworkMemory(strat, ts, conf)
                    } catch (e: Throwable) {}
                }
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
        val sourcePrefs = if (prefs.all.isNotEmpty()) prefs else context.getSharedPreferences("dpi_engine_host_memory", Context.MODE_PRIVATE)

        sourcePrefs.all.forEach { (host, value) ->
            if (value is String) {
                val parts = value.split("|")
                if (parts.size >= 2) {
                    try {
                        val strat = BypassStrategy.valueOf(parts[0])
                        val ts = parts[1].toLong()
                        val successCount = if (parts.size >= 3) parts[2].toIntOrNull() ?: 1 else 1
                        if (now - ts < expiry) {
                            DpiEngine.hostSpecificMemory[host] = DpiEngine.HostMemory(strat, ts, successCount)
                        }
                    } catch (e: Throwable) {}
                }
            }
        }

        val blPrefs = context.getSharedPreferences("dpi_host_bl_$profileId", Context.MODE_PRIVATE)
        val sourceBlPrefs = if (blPrefs.all.isNotEmpty()) blPrefs else context.getSharedPreferences("dpi_engine_host_blacklist", Context.MODE_PRIVATE)

        sourceBlPrefs.all.forEach { (host, value) ->
            if (value is String) {
                val map = DpiEngine.hostStrategyBlacklist.getOrPut(host) { ConcurrentHashMap() }
                value.split(",").forEach { entry ->
                    val parts = entry.split(":")
                    if (parts.size == 2) {
                        try {
                            val strat = BypassStrategy.valueOf(parts[0])
                            val until = parts[1].toLong()
                            if (until > now) {
                                map[strat] = until
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
                // Evict the least recently used profile using timestamp
                val oldest = allProfiles.minByOrNull { id -> registry.getLong("ts_$id", 0L) }
                if (oldest != null && oldest != profileId) {
                    allProfiles.remove(oldest)
                    editor.remove("ts_$oldest")
                    context.getSharedPreferences("dpi_scores_$oldest", Context.MODE_PRIVATE).edit().clear().apply()
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
}


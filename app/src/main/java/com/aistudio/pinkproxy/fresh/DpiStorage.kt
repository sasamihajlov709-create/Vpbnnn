package com.aistudio.pinkproxy.fresh

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

object DpiStorage {

    fun saveScores(context: Context) {
        saveHostMemory(context)
        val prefs = context.getSharedPreferences("dpi_engine_scores", Context.MODE_PRIVATE)
        val editor = prefs.edit()
        editor.clear()
        DpiEngine.strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                editor.putInt("${cat.name}_${strat.name}", score.get())
            }
        }
        DpiEngine.networkStrategyMemory.forEach { (netType, catMap) ->
            catMap.forEach { (cat, mem) ->
                editor.putString("netmem_${netType}::${cat.name}", "${mem.strategy.name}|${mem.timestamp}|${mem.confidence}")
            }
        }
        editor.apply()
    }

    fun loadScores(context: Context) {
        loadHostMemory(context)
        val prefs = context.getSharedPreferences("dpi_engine_scores", Context.MODE_PRIVATE)
        DpiEngine.strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                val saved = prefs.getInt("${cat.name}_${strat.name}", -1)
                if (saved != -1) score.set(saved)
            }
        }
        prefs.all.keys.filter { it.startsWith("netmem_") }.forEach { key ->
            val raw = key.removePrefix("netmem_")
            val parts = if (raw.contains("::")) raw.split("::", limit = 2) else raw.split("_", limit = 2)
            if (parts.size == 2) {
                val netType = parts[0]
                val catName = parts[1]
                val valStr = prefs.getString(key, null)
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

    private fun saveHostMemory(context: Context) {
        val prefs = context.getSharedPreferences("dpi_engine_host_memory", Context.MODE_PRIVATE)
        val editor = prefs.edit()
        val now = System.currentTimeMillis()
        val expiry = 86400000L * 7
        DpiEngine.hostSpecificMemory.forEach { (host, mem) ->
            if (now - mem.timestamp < expiry) {
                editor.putString(host, "${mem.strategy.name}|${mem.timestamp}")
            }
        }
        editor.apply()

        val blPrefs = context.getSharedPreferences("dpi_engine_host_blacklist", Context.MODE_PRIVATE)
        val blEditor = blPrefs.edit()
        blEditor.clear()
        DpiEngine.hostStrategyBlacklist.forEach { (host, map) ->
            val validEntries = map.filter { it.value > now }.map { "${it.key.name}:${it.value}" }.joinToString(",")
            if (validEntries.isNotEmpty()) {
                blEditor.putString(host, validEntries)
            }
        }
        blEditor.apply()
    }

    private fun loadHostMemory(context: Context) {
        val prefs = context.getSharedPreferences("dpi_engine_host_memory", Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val expiry = 86400000L * 7
        prefs.all.forEach { (host, value) ->
            if (value is String) {
                val parts = value.split("|")
                if (parts.size == 2) {
                    try {
                        val strat = BypassStrategy.valueOf(parts[0])
                        val ts = parts[1].toLong()
                        if (now - ts < expiry) {
                            DpiEngine.hostSpecificMemory[host] = DpiEngine.HostMemory(strat, ts)
                        }
                    } catch (e: Throwable) {}
                }
            }
        }

        val blPrefs = context.getSharedPreferences("dpi_engine_host_blacklist", Context.MODE_PRIVATE)
        blPrefs.all.forEach { (host, value) ->
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
}

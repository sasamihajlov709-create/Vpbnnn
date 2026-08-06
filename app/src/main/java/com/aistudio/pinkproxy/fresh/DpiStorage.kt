package com.aistudio.pinkproxy.fresh

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

object DpiStorage {

    fun saveScores(context: Context) {
        saveHostMemory(context)
        val prefs = context.getSharedPreferences("dpi_engine_scores", Context.MODE_PRIVATE)
        val editor = prefs.edit()
        DpiEngine.strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                editor.putInt("${cat.name}_${strat.name}", score.get())
            }
        }
        DpiEngine.networkStrategyMemory.forEach { (netType, catMap) ->
            catMap.forEach { (cat, strat) ->
                editor.putString("netmem_${netType}_${cat.name}", strat.name)
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
            val parts = key.removePrefix("netmem_").split("_", limit = 2)
            if (parts.size == 2) {
                val netType = parts[0]
                val catName = parts[1]
                val stratName = prefs.getString(key, null)
                if (stratName != null) {
                    try {
                        val cat = HostCategory.valueOf(catName)
                        val strat = BypassStrategy.valueOf(stratName)
                        val catMap = DpiEngine.networkStrategyMemory.getOrPut(netType) { ConcurrentHashMap() }
                        catMap[cat] = strat
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
    }
}

package com.aistudio.pinkproxy.fresh

import org.json.JSONArray
import org.json.JSONObject

data class StrategyMetricState(
    val score: Int = 100,
    val successCount: Int = 0,
    val failureCount: Int = 0,
    val weightedSuccess: Long = 0L,
    val weightedFailure: Long = 0L,
    val verifiedSuccessCount: Int = 0,
    val totalLatencyMs: Long = 0L,
    val recentLatencies: List<Long> = emptyList(),
    val lastUsedTimestamp: Long = 0L
) {
    fun toJsonObject(): JSONObject {
        val json = JSONObject()
        json.put("score", score)
        json.put("successCount", successCount)
        json.put("failureCount", failureCount)
        json.put("weightedSuccess", weightedSuccess)
        json.put("weightedFailure", weightedFailure)
        json.put("verifiedSuccessCount", verifiedSuccessCount)
        json.put("totalLatencyMs", totalLatencyMs)
        
        val latenciesArr = JSONArray()
        recentLatencies.forEach { latenciesArr.put(it) }
        json.put("recentLatencies", latenciesArr)
        
        json.put("lastUsedTimestamp", lastUsedTimestamp)
        return json
    }

    companion object {
        fun fromJsonObject(json: JSONObject): StrategyMetricState {
            val recentLatencies = mutableListOf<Long>()
            val arr = json.optJSONArray("recentLatencies")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    recentLatencies.add(arr.optLong(i))
                }
            }

            return StrategyMetricState(
                score = json.optInt("score", 100),
                successCount = json.optInt("successCount", 0),
                failureCount = json.optInt("failureCount", 0),
                weightedSuccess = json.optLong("weightedSuccess", 0L),
                weightedFailure = json.optLong("weightedFailure", 0L),
                verifiedSuccessCount = json.optInt("verifiedSuccessCount", 0),
                totalLatencyMs = json.optLong("totalLatencyMs", 0L),
                recentLatencies = recentLatencies,
                lastUsedTimestamp = json.optLong("lastUsedTimestamp", 0L)
            )
        }
    }
}

data class HostBlacklistEntry(
    val host: String,
    val transport: TransportType,
    val strategy: BypassStrategy,
    val until: Long
)

data class StrategyProfileState(
    val version: Int = 4,
    val profileId: String,
    val timestamp: Long = System.currentTimeMillis(),
    val networkMemory: Map<HostCategory, NetworkMemory> = emptyMap(),
    val contextualHostMemory: Map<HostContextKey, HostMemory> = emptyMap(),
    val hostBlacklist: List<HostBlacklistEntry> = emptyList(),
    val contextualStrategyStates: Map<StrategyContextKey, StrategyMetricState> = emptyMap()
) {
    fun toJson(): String {
        val root = JSONObject()
        root.put("version", version)
        root.put("profileId", profileId)
        root.put("timestamp", timestamp)

        val ctxStatesJson = JSONArray()
        contextualStrategyStates.forEach { (key, metric) ->
            val item = JSONObject()
            item.put("strategy", key.strategy.name)
            item.put("transport", key.transport.name)
            item.put("category", key.category.name)
            item.put("metric", metric.toJsonObject())
            ctxStatesJson.put(item)
        }
        root.put("contextualStrategyStates", ctxStatesJson)

        val netMemJson = JSONObject()
        networkMemory.forEach { (cat, mem) ->
            val memObj = JSONObject()
            memObj.put("strategy", mem.strategy.name)
            memObj.put("timestamp", mem.timestamp)
            memObj.put("confidence", mem.confidence)
            netMemJson.put(cat.name, memObj)
        }
        root.put("networkMemory", netMemJson)

        val ctxHostMemJson = JSONObject()
        contextualHostMemory.forEach { (ctxKey, mem) ->
            val memObj = JSONObject()
            memObj.put("strategy", mem.strategy.name)
            memObj.put("timestamp", mem.timestamp)
            memObj.put("successCount", mem.successCount)
            memObj.put("transport", mem.transport.name)
            memObj.put("profileId", mem.profileId)
            memObj.put("confidence", mem.confidence)
            ctxHostMemJson.put(ctxKey.toStorageString(), memObj)
        }
        root.put("contextualHostMemory", ctxHostMemJson)

        val hostBlJson = JSONArray()
        hostBlacklist.forEach { entry ->
            val blObj = JSONObject()
            blObj.put("host", entry.host)
            blObj.put("transport", entry.transport.name)
            blObj.put("strategy", entry.strategy.name)
            blObj.put("until", entry.until)
            hostBlJson.put(blObj)
        }
        root.put("hostBlacklistList", hostBlJson)

        return root.toString()
    }

    companion object {
        fun fromJson(jsonStr: String): StrategyProfileState? {
            try {
                val root = JSONObject(jsonStr)
                val version = root.optInt("version", 2)
                val profileId = root.optString("profileId", "default")
                val timestamp = root.optLong("timestamp", System.currentTimeMillis())

                val ctxStates = mutableMapOf<StrategyContextKey, StrategyMetricState>()
                val ctxStatesJson = root.optJSONArray("contextualStrategyStates")
                if (ctxStatesJson != null) {
                    for (i in 0 until ctxStatesJson.length()) {
                        val item = ctxStatesJson.optJSONObject(i)
                        if (item != null) {
                            val stratStr = item.optString("strategy")
                            val transStr = item.optString("transport")
                            val catStr = item.optString("category")
                            val metricObj = item.optJSONObject("metric")
                            if (metricObj != null) {
                                try {
                                    val strategy = BypassStrategy.valueOf(stratStr)
                                    val trans = TransportType.valueOf(transStr)
                                    val cat = HostCategory.valueOf(catStr)
                                    val key = StrategyContextKey(strategy, trans, cat, profileId)
                                    ctxStates[key] = StrategyMetricState.fromJsonObject(metricObj)
                                } catch (e: Exception) {
                                }
                            }
                        }
                    }
                }

                val netMem = mutableMapOf<HostCategory, NetworkMemory>()
                val netMemJson = root.optJSONObject("networkMemory")
                if (netMemJson != null) {
                    val keys = netMemJson.keys()
                    while (keys.hasNext()) {
                        val catName = keys.next()
                        val cat = try { HostCategory.valueOf(catName) } catch (e: Exception) { null }
                        val memObj = netMemJson.optJSONObject(catName)
                        if (cat != null && memObj != null) {
                            val strategy = try { BypassStrategy.valueOf(memObj.optString("strategy")) } catch (e: Exception) { null }
                            if (strategy != null) {
                                netMem[cat] = NetworkMemory(
                                    strategy = strategy,
                                    timestamp = memObj.optLong("timestamp", System.currentTimeMillis()),
                                    confidence = memObj.optDouble("confidence", 1.0)
                                )
                            }
                        }
                    }
                }

                val ctxHostMem = mutableMapOf<HostContextKey, HostMemory>()
                val ctxHostMemJson = root.optJSONObject("contextualHostMemory")
                if (ctxHostMemJson != null) {
                    val keys = ctxHostMemJson.keys()
                    while (keys.hasNext()) {
                        val keyStr = keys.next()
                        val memObj = ctxHostMemJson.optJSONObject(keyStr)
                        if (memObj != null) {
                            val strategy = try { BypassStrategy.valueOf(memObj.optString("strategy")) } catch (e: Exception) { null }
                            if (strategy != null) {
                                val ctxKey = HostContextKey.fromStorageString(keyStr)
                                val trans = try { TransportType.valueOf(memObj.optString("transport", ctxKey.transport.name)) } catch (e: Exception) { ctxKey.transport }
                                val prof = memObj.optString("profileId", ctxKey.profileId)
                                val mem = HostMemory(
                                    strategy = strategy,
                                    timestamp = memObj.optLong("timestamp", System.currentTimeMillis()),
                                    successCount = memObj.optInt("successCount", 1),
                                    transport = trans,
                                    profileId = prof,
                                    confidence = memObj.optDouble("confidence", 1.0)
                                )
                                ctxHostMem[ctxKey] = mem
                            }
                        }
                    }
                }

                val hostBl = mutableListOf<HostBlacklistEntry>()
                val hostBlListJson = root.optJSONArray("hostBlacklistList")
                if (hostBlListJson != null) {
                    for (i in 0 until hostBlListJson.length()) {
                        val item = hostBlListJson.optJSONObject(i)
                        if (item != null) {
                            val host = item.optString("host")
                            val trans = try { TransportType.valueOf(item.optString("transport")) } catch (e: Exception) { TransportType.TCP }
                            val strat = try { BypassStrategy.valueOf(item.optString("strategy")) } catch (e: Exception) { null }
                            val until = item.optLong("until", 0L)
                            if (host.isNotEmpty() && strat != null) {
                                hostBl.add(HostBlacklistEntry(host, trans, strat, until))
                            }
                        }
                    }
                } else {
                    // Legacy parsing
                    val hostBlJson = root.optJSONObject("hostBlacklist")
                    if (hostBlJson != null) {
                        val keys = hostBlJson.keys()
                        while (keys.hasNext()) {
                            val host = keys.next()
                            val blObj = hostBlJson.optJSONObject(host)
                            if (blObj != null) {
                                val blKeys = blObj.keys()
                                while (blKeys.hasNext()) {
                                    val stratName = blKeys.next()
                                    val strategy = try { BypassStrategy.valueOf(stratName) } catch (e: Exception) { null }
                                    if (strategy != null) {
                                        hostBl.add(HostBlacklistEntry(host, TransportType.TCP, strategy, blObj.optLong(stratName, 0L)))
                                    }
                                }
                            }
                        }
                    }
                }

                return StrategyProfileState(
                    version = version,
                    profileId = profileId,
                    timestamp = timestamp,
                    networkMemory = netMem,
                    contextualHostMemory = ctxHostMem,
                    hostBlacklist = hostBl,
                    contextualStrategyStates = ctxStates
                )
            } catch (e: Exception) {
                return null
            }
        }
    }
}

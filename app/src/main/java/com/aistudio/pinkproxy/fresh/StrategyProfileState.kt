package com.aistudio.pinkproxy.fresh

import org.json.JSONArray
import org.json.JSONObject

data class StrategyMetricState(
    val score: Int = 100,
    val successCount: Int = 0,
    val failureCount: Int = 0,
    val weightedSuccess: Long = 0L,
    val verifiedSuccessCount: Int = 0,
    val totalLatencyMs: Long = 0L,
    val lastUsedTimestamp: Long = 0L
) {
    fun toJsonObject(): JSONObject {
        val json = JSONObject()
        json.put("score", score)
        json.put("successCount", successCount)
        json.put("failureCount", failureCount)
        json.put("weightedSuccess", weightedSuccess)
        json.put("verifiedSuccessCount", verifiedSuccessCount)
        json.put("totalLatencyMs", totalLatencyMs)
        json.put("lastUsedTimestamp", lastUsedTimestamp)
        return json
    }

    companion object {
        fun fromJsonObject(json: JSONObject): StrategyMetricState {
            return StrategyMetricState(
                score = json.optInt("score", 100),
                successCount = json.optInt("successCount", 0),
                failureCount = json.optInt("failureCount", 0),
                weightedSuccess = json.optLong("weightedSuccess", 0L),
                verifiedSuccessCount = json.optInt("verifiedSuccessCount", 0),
                totalLatencyMs = json.optLong("totalLatencyMs", 0L),
                lastUsedTimestamp = json.optLong("lastUsedTimestamp", 0L)
            )
        }
    }
}

data class StrategyProfileState(
    val version: Int = 3,
    val profileId: String,
    val timestamp: Long = System.currentTimeMillis(),
    val networkMemory: Map<HostCategory, DpiEngine.NetworkMemory> = emptyMap(),
    val contextualHostMemory: Map<HostContextKey, DpiEngine.HostMemory> = emptyMap(),
    val hostBlacklist: Map<String, Map<BypassStrategy, Long>> = emptyMap(),
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

        val hostBlJson = JSONObject()
        hostBlacklist.forEach { (host, map) ->
            val blObj = JSONObject()
            map.forEach { (strategy, until) ->
                blObj.put(strategy.name, until)
            }
            hostBlJson.put(host, blObj)
        }
        root.put("hostBlacklist", hostBlJson)

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

                val netMem = mutableMapOf<HostCategory, DpiEngine.NetworkMemory>()
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
                                netMem[cat] = DpiEngine.NetworkMemory(
                                    strategy = strategy,
                                    timestamp = memObj.optLong("timestamp", System.currentTimeMillis()),
                                    confidence = memObj.optDouble("confidence", 1.0)
                                )
                            }
                        }
                    }
                }

                val ctxHostMem = mutableMapOf<HostContextKey, DpiEngine.HostMemory>()
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
                                val mem = DpiEngine.HostMemory(
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

                val hostBl = mutableMapOf<String, Map<BypassStrategy, Long>>()
                val hostBlJson = root.optJSONObject("hostBlacklist")
                if (hostBlJson != null) {
                    val keys = hostBlJson.keys()
                    while (keys.hasNext()) {
                        val host = keys.next()
                        val blObj = hostBlJson.optJSONObject(host)
                        if (blObj != null) {
                            val map = mutableMapOf<BypassStrategy, Long>()
                            val blKeys = blObj.keys()
                            while (blKeys.hasNext()) {
                                val stratName = blKeys.next()
                                val strategy = try { BypassStrategy.valueOf(stratName) } catch (e: Exception) { null }
                                if (strategy != null) {
                                    map[strategy] = blObj.optLong(stratName, 0L)
                                }
                            }
                            if (map.isNotEmpty()) {
                                hostBl[host] = map
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

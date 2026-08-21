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
    val version: Int = 2,
    val profileId: String,
    val timestamp: Long = System.currentTimeMillis(),
    val metricsByCategory: Map<HostCategory, Map<BypassStrategy, StrategyMetricState>> = emptyMap(),
    val globalWeightedSuccess: Map<BypassStrategy, Long> = emptyMap(),
    val networkMemory: Map<HostCategory, DpiEngine.NetworkMemory> = emptyMap(),
    val hostMemory: Map<String, DpiEngine.HostMemory> = emptyMap(),
    val contextualHostMemory: Map<HostContextKey, DpiEngine.HostMemory> = emptyMap(),
    val hostBlacklist: Map<String, Map<BypassStrategy, Long>> = emptyMap(),
    val contextualStrategyStates: Map<StrategyContextKey, StrategyMetricState> = emptyMap()
) {
    fun toJson(): String {
        val root = JSONObject()
        root.put("version", version)
        root.put("profileId", profileId)
        root.put("timestamp", timestamp)

        // metricsByCategory
        val metricsJson = JSONObject()
        metricsByCategory.forEach { (cat, stratMap) ->
            val catObj = JSONObject()
            stratMap.forEach { (strat, metric) ->
                catObj.put(strat.name, metric.toJsonObject())
            }
            metricsJson.put(cat.name, catObj)
        }
        root.put("metricsByCategory", metricsJson)

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

        // globalWeightedSuccess
        val globalWeightedJson = JSONObject()
        globalWeightedSuccess.forEach { (strat, weight) ->
            globalWeightedJson.put(strat.name, weight)
        }
        root.put("globalWeightedSuccess", globalWeightedJson)

        // networkMemory
        val netMemJson = JSONObject()
        networkMemory.forEach { (cat, mem) ->
            val memObj = JSONObject()
            memObj.put("strategy", mem.strategy.name)
            memObj.put("timestamp", mem.timestamp)
            memObj.put("confidence", mem.confidence)
            netMemJson.put(cat.name, memObj)
        }
        root.put("networkMemory", netMemJson)

        // contextualHostMemory & hostMemory
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

        val hostMemJson = JSONObject()
        hostMemory.forEach { (host, mem) ->
            val memObj = JSONObject()
            memObj.put("strategy", mem.strategy.name)
            memObj.put("timestamp", mem.timestamp)
            memObj.put("successCount", mem.successCount)
            memObj.put("transport", mem.transport.name)
            memObj.put("profileId", mem.profileId)
            memObj.put("confidence", mem.confidence)
            hostMemJson.put(host, memObj)
        }
        root.put("hostMemory", hostMemJson)

        // hostBlacklist
        val hostBlJson = JSONObject()
        hostBlacklist.forEach { (host, map) ->
            val blMapObj = JSONObject()
            map.forEach { (strat, until) ->
                blMapObj.put(strat.name, until)
            }
            hostBlJson.put(host, blMapObj)
        }
        root.put("hostBlacklist", hostBlJson)

        return root.toString()
    }

    companion object {
        fun fromJson(jsonStr: String): StrategyProfileState? {
            return try {
                val root = JSONObject(jsonStr)
                val version = root.optInt("version", 1)
                val profileId = root.optString("profileId", "default")
                val timestamp = root.optLong("timestamp", System.currentTimeMillis())

                val metricsMap = mutableMapOf<HostCategory, Map<BypassStrategy, StrategyMetricState>>()
                val metricsJson = root.optJSONObject("metricsByCategory")
                if (metricsJson != null) {
                    val keys = metricsJson.keys()
                    while (keys.hasNext()) {
                        val catName = keys.next()
                        val cat = try { HostCategory.valueOf(catName) } catch (e: Exception) { null }
                        val catObj = metricsJson.optJSONObject(catName)
                        if (cat != null && catObj != null) {
                            val strats = mutableMapOf<BypassStrategy, StrategyMetricState>()
                            val stratKeys = catObj.keys()
                            while (stratKeys.hasNext()) {
                                val stratName = stratKeys.next()
                                val strat = try { BypassStrategy.valueOf(stratName) } catch (e: Exception) { null }
                                val metricObj = catObj.optJSONObject(stratName)
                                if (strat != null && metricObj != null) {
                                    strats[strat] = StrategyMetricState.fromJsonObject(metricObj)
                                }
                            }
                            if (strats.isNotEmpty()) {
                                metricsMap[cat] = strats
                            }
                        }
                    }
                }

                val ctxStates = mutableMapOf<StrategyContextKey, StrategyMetricState>()
                val ctxStatesArray = root.optJSONArray("contextualStrategyStates")
                if (ctxStatesArray != null) {
                    for (i in 0 until ctxStatesArray.length()) {
                        val item = ctxStatesArray.optJSONObject(i)
                        if (item != null) {
                            val stratStr = item.optString("strategy")
                            val transStr = item.optString("transport")
                            val catStr = item.optString("category")
                            val metricObj = item.optJSONObject("metric")
                            if (metricObj != null) {
                                try {
                                    val strat = BypassStrategy.valueOf(stratStr)
                                    val trans = TransportType.valueOf(transStr)
                                    val cat = HostCategory.valueOf(catStr)
                                    val key = StrategyContextKey(strat, trans, cat, profileId)
                                    ctxStates[key] = StrategyMetricState.fromJsonObject(metricObj)
                                } catch (e: Exception) {
                                    // ignore parse errors for individual keys
                                }
                            }
                        }
                    }
                }

                val globalWeighted = mutableMapOf<BypassStrategy, Long>()
                val globalWeightedJson = root.optJSONObject("globalWeightedSuccess")
                if (globalWeightedJson != null) {
                    val keys = globalWeightedJson.keys()
                    while (keys.hasNext()) {
                        val stratName = keys.next()
                        val strat = try { BypassStrategy.valueOf(stratName) } catch (e: Exception) { null }
                        if (strat != null) {
                            globalWeighted[strat] = globalWeightedJson.optLong(stratName, 0L)
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
                            val strat = try { BypassStrategy.valueOf(memObj.optString("strategy")) } catch (e: Exception) { null }
                            if (strat != null) {
                                netMem[cat] = DpiEngine.NetworkMemory(
                                    strategy = strat,
                                    timestamp = memObj.optLong("timestamp", System.currentTimeMillis()),
                                    confidence = memObj.optDouble("confidence", 1.0)
                                )
                            }
                        }
                    }
                }

                val hostMem = mutableMapOf<String, DpiEngine.HostMemory>()
                val ctxHostMem = mutableMapOf<HostContextKey, DpiEngine.HostMemory>()
                val ctxHostMemJson = root.optJSONObject("contextualHostMemory")
                if (ctxHostMemJson != null && ctxHostMemJson.length() > 0) {
                    val keys = ctxHostMemJson.keys()
                    while (keys.hasNext()) {
                        val keyStr = keys.next()
                        val memObj = ctxHostMemJson.optJSONObject(keyStr)
                        if (memObj != null) {
                            val strat = try { BypassStrategy.valueOf(memObj.optString("strategy")) } catch (e: Exception) { null }
                            if (strat != null) {
                                val ctxKey = HostContextKey.fromStorageString(keyStr)
                                val trans = try { TransportType.valueOf(memObj.optString("transport", ctxKey.transport.name)) } catch (e: Exception) { ctxKey.transport }
                                val prof = memObj.optString("profileId", ctxKey.profileId)
                                val mem = DpiEngine.HostMemory(
                                    strategy = strat,
                                    timestamp = memObj.optLong("timestamp", System.currentTimeMillis()),
                                    successCount = memObj.optInt("successCount", 1),
                                    transport = trans,
                                    profileId = prof,
                                    confidence = memObj.optDouble("confidence", 1.0)
                                )
                                ctxHostMem[ctxKey] = mem
                                hostMem[ctxKey.host] = mem
                            }
                        }
                    }
                }
                
                val hostMemJson = root.optJSONObject("hostMemory")
                if (hostMemJson != null && hostMemJson.length() > 0) {
                    val keys = hostMemJson.keys()
                    while (keys.hasNext()) {
                        val host = keys.next()
                        val memObj = hostMemJson.optJSONObject(host)
                        if (memObj != null) {
                            val strat = try { BypassStrategy.valueOf(memObj.optString("strategy")) } catch (e: Exception) { null }
                            if (strat != null) {
                                val trans = try { TransportType.valueOf(memObj.optString("transport", TransportType.TCP.name)) } catch (e: Exception) { TransportType.TCP }
                                val prof = memObj.optString("profileId", profileId)
                                val mem = DpiEngine.HostMemory(
                                    strategy = strat,
                                    timestamp = memObj.optLong("timestamp", System.currentTimeMillis()),
                                    successCount = memObj.optInt("successCount", 1),
                                    transport = trans,
                                    profileId = prof,
                                    confidence = memObj.optDouble("confidence", 1.0)
                                )
                                val ctxKey = HostContextKey(host, trans, prof)
                                if (!ctxHostMem.containsKey(ctxKey)) {
                                    ctxHostMem[ctxKey] = mem
                                }
                                if (!hostMem.containsKey(host)) {
                                    hostMem[host] = mem
                                }
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
                                val strat = try { BypassStrategy.valueOf(stratName) } catch (e: Exception) { null }
                                if (strat != null) {
                                    map[strat] = blObj.optLong(stratName, 0L)
                                }
                            }
                            if (map.isNotEmpty()) {
                                hostBl[host] = map
                            }
                        }
                    }
                }

                StrategyProfileState(
                    version = version,
                    profileId = profileId,
                    timestamp = timestamp,
                    metricsByCategory = metricsMap,
                    globalWeightedSuccess = globalWeighted,
                    networkMemory = netMem,
                    hostMemory = hostMem,
                    contextualHostMemory = ctxHostMem,
                    hostBlacklist = hostBl,
                    contextualStrategyStates = ctxStates
                )
            } catch (e: Exception) {
                null
            }
        }
    }
}

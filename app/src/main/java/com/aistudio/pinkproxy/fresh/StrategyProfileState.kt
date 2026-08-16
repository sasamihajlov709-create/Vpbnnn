package com.aistudio.pinkproxy.fresh

import org.json.JSONArray
import org.json.JSONObject

data class StrategyMetricState(
    val score: Int = 100,
    val successCount: Int = 0,
    val failureCount: Int = 0,
    val weightedSuccess: Long = 0L
) {
    fun toJsonObject(): JSONObject {
        val json = JSONObject()
        json.put("score", score)
        json.put("successCount", successCount)
        json.put("failureCount", failureCount)
        json.put("weightedSuccess", weightedSuccess)
        return json
    }

    companion object {
        fun fromJsonObject(json: JSONObject): StrategyMetricState {
            return StrategyMetricState(
                score = json.optInt("score", 100),
                successCount = json.optInt("successCount", 0),
                failureCount = json.optInt("failureCount", 0),
                weightedSuccess = json.optLong("weightedSuccess", 0L)
            )
        }
    }
}

data class StrategyProfileState(
    val version: Int = 1,
    val profileId: String,
    val timestamp: Long = System.currentTimeMillis(),
    val metricsByCategory: Map<HostCategory, Map<BypassStrategy, StrategyMetricState>> = emptyMap(),
    val globalWeightedSuccess: Map<BypassStrategy, Long> = emptyMap(),
    val networkMemory: Map<HostCategory, DpiEngine.NetworkMemory> = emptyMap(),
    val hostMemory: Map<String, DpiEngine.HostMemory> = emptyMap(),
    val hostBlacklist: Map<String, Map<BypassStrategy, Long>> = emptyMap()
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

        // hostMemory
        val hostMemJson = JSONObject()
        hostMemory.forEach { (host, mem) ->
            val memObj = JSONObject()
            memObj.put("strategy", mem.strategy.name)
            memObj.put("timestamp", mem.timestamp)
            memObj.put("successCount", mem.successCount)
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
                val hostMemJson = root.optJSONObject("hostMemory")
                if (hostMemJson != null) {
                    val keys = hostMemJson.keys()
                    while (keys.hasNext()) {
                        val host = keys.next()
                        val memObj = hostMemJson.optJSONObject(host)
                        if (memObj != null) {
                            val strat = try { BypassStrategy.valueOf(memObj.optString("strategy")) } catch (e: Exception) { null }
                            if (strat != null) {
                                hostMem[host] = DpiEngine.HostMemory(
                                    strategy = strat,
                                    timestamp = memObj.optLong("timestamp", System.currentTimeMillis()),
                                    successCount = memObj.optInt("successCount", 1)
                                )
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
                    hostBlacklist = hostBl
                )
            } catch (e: Exception) {
                null
            }
        }
    }
}

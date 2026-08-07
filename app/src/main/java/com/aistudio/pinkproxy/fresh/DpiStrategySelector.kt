package com.aistudio.pinkproxy.fresh

import android.util.Log
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicInteger

object DpiStrategySelector {

    fun getBestStrategy(category: HostCategory, host: String? = null): BypassStrategy {
        val now = System.currentTimeMillis()
        val netType = BypassConfig.currentNetworkType.value.toString()
        
        if (DpiEngine.isPanicMode.value || ProxyStats.censorshipIntensity.value > 92) {
             return getBestExtremeStrategy(host)
        }

        if (host != null) {
            val hostFails = DpiEngine.consecutiveFailuresByHost[host]?.get() ?: 0
            if (hostFails > 4) {
                val lastMem = DpiEngine.hostSpecificMemory[host]
                if (lastMem != null) {
                    val escalated = getFallbackStrategy(lastMem.strategy)
                    if (escalated != null && (DpiEngine.circuitBreakers[escalated] ?: 0L) < now) {
                        return escalated
                    }
                }
                return getBestExtremeStrategy(host)
            }
        }

        if (ProxyStats.censorshipIntensity.value > 95) {
            val nuclear = listOf(BypassStrategy.TCP_COMBINED_NUCLEAR, BypassStrategy.UDP_COMBINED_NUCLEAR, BypassStrategy.UDP_RACING)
            val bestNuclear = nuclear.maxByOrNull { getAverageScore(it) } ?: BypassStrategy.TCP_COMBINED_NUCLEAR
            if ((DpiEngine.circuitBreakers[bestNuclear] ?: 0L) < now) return bestNuclear
        } else if (ProxyStats.censorshipIntensity.value > 85) {
            val hybrids = listOf(BypassStrategy.TCP_COMBINED_HYBRID, BypassStrategy.UDP_COMBINED_HYBRID, BypassStrategy.TCP_PULSE_FRAG)
            val bestHybrid = hybrids.maxByOrNull { getAverageScore(it) } ?: BypassStrategy.TCP_COMBINED_HYBRID
            if ((DpiEngine.circuitBreakers[bestHybrid] ?: 0L) < now) return bestHybrid
        }

        DpiEngine.networkStrategyMemory[netType]?.get(category)?.let { strat ->
            if ((DpiEngine.circuitBreakers[strat] ?: 0L) < now) {
                val hostBlacklist = host?.let { DpiEngine.hostStrategyBlacklist[it] }
                val blacklistedUntil = hostBlacklist?.get(strat) ?: 0L
                if (blacklistedUntil < now) {
                    return strat
                }
            }
        }

        val catScores = DpiEngine.strategyScores[category] ?: return BypassStrategy.SNI_SPLIT
        
        val hostBlacklist = host?.let { DpiEngine.hostStrategyBlacklist[it] }
        val validStrategies = catScores.entries.filter { (strat, _) ->
            (DpiEngine.circuitBreakers[strat] ?: 0L) < now && 
            (hostBlacklist?.get(strat) ?: 0L) < now &&
            (!BypassConfig.isStrictBypassMode || strat != BypassStrategy.DIRECT)
        }
        
        if (validStrategies.isEmpty()) {
            if (host != null) DpiEngine.hostStrategyBlacklist.remove(host)
            DpiEngine.circuitBreakers.entries.removeIf { it.value < now }
            return BypassStrategy.CHAOS
        }

        val rnd = ThreadLocalRandom.current()
        if (rnd.nextInt(100) < 7) {
            return validStrategies.random().key
        }

        val weightedList = mutableListOf<Pair<BypassStrategy, Double>>()
        var currentTotal = 0.0
        val currentDpi = ProxyStats.currentDpiType.value
        
        for ((strat, sRaw) in validStrategies) {
            var s = sRaw.get().toDouble()
            
            val gPenalty = DpiEngine.globalPenalties[strat]?.get() ?: 0
            val gBoost = DpiEngine.globalBoosts[strat]?.get() ?: 0
            s = (s - gPenalty + gBoost).coerceAtLeast(1.0)

            val globalScore = ProxyStats.getStrategyScore(strat).toDouble()
            if (globalScore > 0) s += globalScore * 5
            else if (globalScore < 0) s += globalScore * 10
            
            s = s.coerceAtLeast(1.0)
            s += (DpiEngine.strategyMaturity[strat]?.get() ?: 0) / 6.0
            
            when (currentDpi) {
                DpiType.TLS_SNI_BLOCK -> if (strat.family == StrategyFamily.TLS || strat.family == StrategyFamily.FRAGMENTATION) s *= 2.0
                DpiType.TCP_RESET -> if (strat.family == StrategyFamily.TCP || strat.family == StrategyFamily.FRAGMENTATION) s *= 2.0
                DpiType.UDP_BLOCK -> if (strat.family == StrategyFamily.UDP || strat.family == StrategyFamily.QUIC) s *= 2.2
                DpiType.BLACKHOLE -> if (strat.group == StrategyGroup.EXTREME || strat.group == StrategyGroup.HEAVY) s *= 2.8
                else -> {}
            }

            // Censorship Intensity Tier Weighting
            val intensity = ProxyStats.censorshipIntensity.value
            when {
                intensity > 90 -> {
                    if (strat.group == StrategyGroup.EXTREME) s *= 2.5
                    else if (strat.group == StrategyGroup.HEAVY) s *= 1.8
                    else s *= 0.4
                }
                intensity > 70 -> {
                    if (strat.group == StrategyGroup.HEAVY || strat.group == StrategyGroup.EXTREME) s *= 1.8
                    else if (strat.group == StrategyGroup.MEDIUM) s *= 1.2
                    else s *= 0.6
                }
                intensity > 30 -> {
                    if (strat.group == StrategyGroup.MEDIUM || strat.group == StrategyGroup.HEAVY) s *= 1.5
                    else if (strat.group == StrategyGroup.LIGHT) s *= 1.2
                }
                else -> {
                    if (strat.group == StrategyGroup.LIGHT || strat.group == StrategyGroup.MEDIUM) s *= 1.6
                    else s *= 0.7
                }
            }
            
            // Category-Specific Weighting Matrix
            when (category) {
                HostCategory.STREAMING, HostCategory.GAMING -> {
                    if (strat.family == StrategyFamily.UDP || strat.family == StrategyFamily.QUIC || strat == BypassStrategy.SNI_SPLIT || strat == BypassStrategy.TLS_RECORD_FRAGMENTATION) s *= 1.8
                    if (strat.family == StrategyFamily.TIMING) s *= 0.7 // Avoid timing delays for real-time traffic
                }
                HostCategory.SOCIAL, HostCategory.MESSENGER -> {
                    if (strat == BypassStrategy.HTTP_MULTI_LINE_MANGLE || strat == BypassStrategy.BYEBYEDPI_HYBRID || strat == BypassStrategy.TCP_COMBINED_HYBRID || strat == BypassStrategy.TLS_SNI_EXT_MANGLE) s *= 1.9
                }
                HostCategory.AI, HostCategory.FINANCE -> {
                    if (strat.family == StrategyFamily.FRAGMENTATION || strat == BypassStrategy.TLS_SNI_JITTER_SPLIT || strat == BypassStrategy.TCP_PULSE_FRAG) s *= 1.7
                }
                else -> {}
            }

            // Network Type Specific Weighting
            val netTypeVal = BypassConfig.currentNetworkType.value
            if (netTypeVal == NetworkType.MOBILE || netTypeVal == NetworkType.MOBILE_LOW) {
                if (strat == BypassStrategy.TCP_PULSE_FRAG || strat == BypassStrategy.TLS_SNI_EXT_MANGLE || strat == BypassStrategy.SNI_SPLIT) s *= 1.5
                if (strat == BypassStrategy.TCP_COMBINED_NUCLEAR) s *= 0.85 // Heavy desync can drop on mobile towers
            } else if (netTypeVal == NetworkType.WIFI || netTypeVal == NetworkType.ETHERNET) {
                if (strat.group == StrategyGroup.EXTREME) s *= 1.3
            }

            if (BypassConfig.isPowerSaveMode || BypassConfig.batteryLevel < 20) {
                when (strat.group) {
                    StrategyGroup.EXTREME -> s *= 0.2
                    StrategyGroup.HEAVY -> s *= 0.5
                    StrategyGroup.MEDIUM -> s *= 0.8
                    StrategyGroup.LIGHT -> s *= 1.5
                }
            }
            if (BypassConfig.thermalStatus >= 3) {
                 if (strat.group == StrategyGroup.EXTREME || strat.group == StrategyGroup.HEAVY) s *= 0.3
            }
            
            val latency = DpiEngine.strategyLatency[strat]?.get() ?: 200L
            val latencyPenalty = (latency / 15.0).coerceAtMost(60.0)
            val weight = (s - latencyPenalty).coerceAtLeast(5.0)
            
            weightedList.add(strat to weight)
            currentTotal += weight
        }

        if (currentTotal <= 0 || weightedList.isEmpty()) {
            return validStrategies.maxByOrNull { it.value.get() }?.key ?: BypassStrategy.SNI_SPLIT
        }

        var randomPivot = rnd.nextDouble() * currentTotal
        for ((strat, weight) in weightedList) {
            randomPivot -= weight
            if (randomPivot <= 1e-9) return strat
        }

        return weightedList.last().first
    }

    fun getBestExtremeStrategy(host: String? = null): BypassStrategy {
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        val extreme = DpiEngine.strategyScores[cat]?.entries?.filter { it.key.group == StrategyGroup.EXTREME } ?: emptyList()
        if (extreme.isEmpty()) {
            return BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME }
                .maxByOrNull { getAverageScore(it) } ?: BypassStrategy.ZAPRET_EXTREME
        }
        return extreme.maxByOrNull { it.value.get() }?.key ?: BypassStrategy.ZAPRET_EXTREME
    }

    fun getFallbackStrategy(failedStrategy: BypassStrategy): BypassStrategy? {
        return DpiEngine.strategyChains[failedStrategy]
    }

    fun getDiverseFallback(failed: BypassStrategy? = null, category: HostCategory? = null): BypassStrategy {
        val candidates = BypassStrategy.entries.filter { 
            (it.group == StrategyGroup.EXTREME || it.group == StrategyGroup.HEAVY) && 
            it != failed
        }
        
        if (candidates.isEmpty()) return BypassStrategy.ZAPRET_EXTREME

        // Try to select a family that fits the category, or a different one than the failed one
        val preferred = when(category) {
            HostCategory.STREAMING, HostCategory.GAMING -> candidates.filter { it.family == StrategyFamily.UDP || it.family == StrategyFamily.QUIC }
            HostCategory.AI, HostCategory.SOCIAL -> candidates.filter { it.family == StrategyFamily.FRAGMENTATION || it.family == StrategyFamily.TLS }
            else -> candidates.filter { failed == null || it.family != failed.family }
        }.ifEmpty { candidates }

        return preferred.random()
    }

    fun recordResult(strategy: BypassStrategy, success: Boolean, category: HostCategory = HostCategory.OTHER, reason: FailureReason? = null, latencyMs: Long = 0, host: String? = null) {
        if (success) {
            DpiEngine.successHistory.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            DpiEngine.strategyMaturity.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            DpiEngine.globalPenalties[strategy]?.updateAndGet { (it * 0.8).toInt() }
            DpiEngine.globalBoosts.getOrPut(strategy) { AtomicInteger(0) }.addAndGet(5)

            DpiEngine.strategyScores[category]?.get(strategy)?.let { score ->
                var bonus = if (latencyMs in 1..300) 35 else 15
                val intensity = ProxyStats.censorshipIntensity.value
                if (intensity > 50) {
                    bonus += (intensity / 10) * 5
                }
                score.addAndGet(bonus)
                if (score.get() > 3000) score.set(3000)
            }
            
            if (host != null) {
                DpiEngine.hostStrategyBlacklist[host]?.remove(strategy)
                DpiEngine.consecutiveFailuresByHost[host]?.set(0)
                DpiEngine.hostSpecificMemory[host] = DpiEngine.HostMemory(strategy, System.currentTimeMillis())
                
                val netType = BypassConfig.currentNetworkType.value.toString()
                val netMemory = DpiEngine.networkStrategyMemory.getOrPut(netType) { java.util.concurrent.ConcurrentHashMap() }
                if ((DpiEngine.strategyMaturity[strategy]?.get() ?: 0) > 3) {
                    netMemory[category] = strategy
                }
            }

            if (latencyMs > 0) {
                val currentAvg = DpiEngine.strategyLatency.getOrPut(strategy) { java.util.concurrent.atomic.AtomicLong(0) }
                if (currentAvg.get() == 0L) currentAvg.set(latencyMs)
                else currentAvg.set((currentAvg.get() * 7 + latencyMs) / 8)
            }
            DpiEngine.consecutiveFailures.remove(strategy)
            DpiEngine.circuitBreakers.remove(strategy)
        } else {
            DpiEngine.failureHistory.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            if (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL) {
                ProxyStats.recordCensorshipEvent(true)
            }
            if (host != null) {
                DpiEngine.consecutiveFailuresByHost.getOrPut(host) { AtomicInteger(0) }.incrementAndGet()
            }

            val hostFails = host?.let { DpiEngine.consecutiveFailuresByHost[it]?.get() } ?: 0
            val expMultiplier = Math.pow(1.35, hostFails.toDouble().coerceAtMost(5.0))
            val basePenalty = when (reason) {
                FailureReason.TCP_RESET -> {
                    DpiEngine.globalPenalties.getOrPut(strategy) { AtomicInteger(0) }.addAndGet(50)
                    DpiEngine.globalBoosts[strategy]?.set(0)
                    120
                }
                FailureReason.CENSORSHIP_STALL -> {
                    DpiEngine.globalPenalties.getOrPut(strategy) { AtomicInteger(0) }.addAndGet(80)
                    DpiEngine.globalBoosts[strategy]?.set(0)
                    150
                }
                else -> 40
            }
            val finalPenalty = (basePenalty * expMultiplier).toInt()
            DpiEngine.strategyScores[category]?.get(strategy)?.let { score ->
                score.addAndGet(-finalPenalty)
                score.set((score.get() * 0.85).toInt().coerceAtLeast(0))
            }
            
            val fails = DpiEngine.consecutiveFailures.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            if (fails >= 4 || (fails >= 2 && reason == FailureReason.TCP_RESET)) {
                val duration = if (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL) 600_000L else 300_000L
                DpiEngine.circuitBreakers[strategy] = System.currentTimeMillis() + duration
                DpiEngine.consecutiveFailures.remove(strategy)
            }
            if (host != null && (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL)) {
                val hostBlacklist = DpiEngine.hostStrategyBlacklist.getOrPut(host) { java.util.concurrent.ConcurrentHashMap() }
                val currentLevel = hostBlacklist[strategy] ?: 0L
                val waitTime = if (System.currentTimeMillis() > currentLevel) 900_000L else 3_600_000L
                hostBlacklist[strategy] = System.currentTimeMillis() + waitTime
            }
        }
    }

    fun getAverageScore(strategy: BypassStrategy): Double {
        val scores = DpiEngine.strategyScores.values.map { it[strategy]?.get() ?: 0 }.map { it.toDouble() }
        if (scores.isEmpty()) return 0.0
        return scores.average()
    }

    fun getStrategyMetrics(): List<StrategyMetric> {
        return BypassStrategy.entries.map { strat ->
            val successes = DpiEngine.successHistory[strat]?.get()?.toLong() ?: 0L
            val failures = DpiEngine.failureHistory[strat]?.get()?.toLong() ?: 0L
            val avgRtt = DpiEngine.strategyLatency[strat]?.get() ?: 0L
            val score = getAverageScore(strat).toInt()
            StrategyMetric(strat, score, successes, failures, avgRtt)
        }.sortedByDescending { it.score }
    }

    fun getSelectionReasoning(strategy: BypassStrategy): String {
        val intensity = ProxyStats.censorshipIntensity.value
        val dpiType = ProxyStats.currentDpiType.value
        
        if (intensity > 90) return "Extreme censorship detected ($intensity%). Using heavy evasion."
        if (dpiType == DpiType.TLS_SNI_BLOCK) return "SNI blocking detected. Prioritizing TLS fragmentation."
        if (dpiType == DpiType.TCP_RESET) return "TCP Resets detected. Using robust packet mangling."
        if (dpiType == DpiType.UDP_BLOCK) return "UDP/QUIC throttling detected. Racing TCP protocols."
        
        val score = getAverageScore(strategy).toInt()
        if (score > 1000) return "Strategy is highly stable for current network."
        if (score < 100) return "Exploring new paths due to failures."
        
        return "Optimal balance of speed and evasion for ${strategy.family.name} traffic."
    }
}

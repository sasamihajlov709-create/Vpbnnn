package com.aistudio.pinkproxy.fresh

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicInteger

object DpiStrategySelector {

    fun isFamilyCompatible(family: StrategyFamily, transport: TransportType): Boolean {
        return when (transport) {
            TransportType.TCP -> family != StrategyFamily.UDP && family != StrategyFamily.QUIC && family != StrategyFamily.DNS
            TransportType.UDP -> family != StrategyFamily.TCP && family != StrategyFamily.TLS && family != StrategyFamily.HTTP && family != StrategyFamily.FRAGMENTATION && family != StrategyFamily.TIMING && family != StrategyFamily.DNS
            TransportType.DNS -> family == StrategyFamily.DNS || family == StrategyFamily.DIRECT
        }
    }

    fun getDefaultFallback(transport: TransportType): BypassStrategy {
        return when (transport) {
            TransportType.TCP -> BypassStrategy.SNI_SPLIT
            TransportType.UDP -> BypassStrategy.UDP_COMBINED_HYBRID
            TransportType.DNS -> BypassStrategy.DNS_OVER_TCP
        }
    }

    fun getDefaultExtremeFallback(transport: TransportType): BypassStrategy {
        return when (transport) {
            TransportType.TCP -> BypassStrategy.ZAPRET_EXTREME
            TransportType.UDP -> BypassStrategy.UDP_COMBINED_NUCLEAR
            TransportType.DNS -> BypassStrategy.DNS_OVER_TCP_FORCE
        }
    }

    fun getBestStrategy(category: HostCategory, host: String? = null, transport: TransportType = TransportType.TCP): BypassStrategy {
        val now = System.currentTimeMillis()
        val netType = BypassConfig.currentNetworkType.value.toString()
        
        if (DpiEngine.isPanicMode.value || ProxyStats.censorshipIntensity.value > 92) {
             return getBestExtremeStrategy(host, transport)
        }

        if (host != null) {
            val hostFails = DpiEngine.consecutiveFailuresByHost[host]?.get() ?: 0
            if (hostFails == 0) {
                val lastMem = DpiEngine.hostSpecificMemory[host]
                if (lastMem != null && (lastMem.successCount >= 2 || (now - lastMem.timestamp < 300_000L)) && (now - lastMem.timestamp < 24 * 3600 * 1000L)) {
                    val strat = lastMem.strategy
                    if (isFamilyCompatible(strat.family, transport) && StrategyExecutionRegistry.isExecutorSupported(strat, transport) && (DpiEngine.circuitBreakers[strat] ?: 0L) < now) {
                        val hostBlacklist = DpiEngine.hostStrategyBlacklist[host]
                        if ((hostBlacklist?.get(strat) ?: 0L) < now) {
                            return strat
                        }
                    }
                }
            } else if (hostFails > 2) {
                val lastMem = DpiEngine.hostSpecificMemory[host]
                if (lastMem != null) {
                    var currentStep: BypassStrategy? = lastMem.strategy
                    for (i in 0 until (hostFails - 2)) {
                        currentStep = currentStep?.let { getFallbackStrategy(it, transport) }
                    }
                    if (currentStep != null && isFamilyCompatible(currentStep.family, transport) && StrategyExecutionRegistry.isExecutorSupported(currentStep, transport) && (DpiEngine.circuitBreakers[currentStep] ?: 0L) < now) {
                        val hostBlacklist = DpiEngine.hostStrategyBlacklist[host]
                        if ((hostBlacklist?.get(currentStep) ?: 0L) < now) {
                            return currentStep
                        }
                    }
                }
                return getBestExtremeStrategy(host, transport)
            }
        }

        if (ProxyStats.censorshipIntensity.value > 95) {
            val nuclear = listOf(BypassStrategy.TCP_COMBINED_NUCLEAR, BypassStrategy.UDP_COMBINED_NUCLEAR, BypassStrategy.UDP_RACING, BypassStrategy.DNS_OVER_TCP_FORCE)
                .filter { isFamilyCompatible(it.family, transport) && StrategyExecutionRegistry.isExecutorSupported(it, transport) }
            val bestNuclear = nuclear.maxByOrNull { getAverageScore(it) } ?: getDefaultExtremeFallback(transport)
            if ((DpiEngine.circuitBreakers[bestNuclear] ?: 0L) < now) return bestNuclear
        } else if (ProxyStats.censorshipIntensity.value > 85) {
            val hybrids = listOf(BypassStrategy.TCP_COMBINED_HYBRID, BypassStrategy.UDP_COMBINED_HYBRID, BypassStrategy.TCP_PULSE_FRAG, BypassStrategy.UDP_DNS_REORDER_HYBRID)
                .filter { isFamilyCompatible(it.family, transport) && StrategyExecutionRegistry.isExecutorSupported(it, transport) }
            val bestHybrid = hybrids.maxByOrNull { getAverageScore(it) } ?: getDefaultFallback(transport)
            if ((DpiEngine.circuitBreakers[bestHybrid] ?: 0L) < now) return bestHybrid
        }

        val profileId = NetworkProfileManager.currentProfile.value.id
        val netMem = DpiEngine.networkStrategyMemory[profileId]?.get(category)
            ?: DpiEngine.networkStrategyMemory[netType]?.get(category)

        netMem?.let { mem ->
            val nowMs = System.currentTimeMillis()
            val ageMs = nowMs - mem.timestamp
            val maxAge = 6 * 3600 * 1000L // 6 hours TTL
            if (ageMs < maxAge && mem.confidence >= 0.3) {
                val strat = mem.strategy
                if (isFamilyCompatible(strat.family, transport) && StrategyExecutionRegistry.isExecutorSupported(strat, transport) && (DpiEngine.circuitBreakers[strat] ?: 0L) < now) {
                    val hostBlacklist = host?.let { DpiEngine.hostStrategyBlacklist[it] }
                    val blacklistedUntil = hostBlacklist?.get(strat) ?: 0L
                    if (blacklistedUntil < now) {
                        return strat
                    }
                }
            }
        }

        val catScores = DpiEngine.strategyScores[category] ?: return getDefaultFallback(transport)
        
        val hostBlacklist = host?.let { DpiEngine.hostStrategyBlacklist[it] }
        val validStrategies = catScores.entries.filter { (strat, _) ->
            isFamilyCompatible(strat.family, transport) &&
            StrategyExecutionRegistry.isExecutorSupported(strat, transport) &&
            (DpiEngine.circuitBreakers[strat] ?: 0L) < now && 
            (hostBlacklist?.get(strat) ?: 0L) < now &&
            (!BypassConfig.isStrictBypassMode || strat != BypassStrategy.DIRECT)
        }
        
        if (validStrategies.isEmpty()) {
            if (host != null) DpiEngine.hostStrategyBlacklist.remove(host)
            DpiEngine.circuitBreakers.entries.removeIf { it.value < now }
            return when (transport) {
                TransportType.TCP -> BypassStrategy.CHAOS
                TransportType.UDP -> BypassStrategy.UDP_COMBINED_NUCLEAR
                TransportType.DNS -> BypassStrategy.DNS_OVER_TCP_FORCE
            }
        }

        // Bayesian Thompson Sampling (Multi-Armed Bandit) integration
        val catSuccessMap = DpiEngine.categorySuccessHistory[category]
        val catFailureMap = DpiEngine.categoryFailureHistory[category]

        val weightedList = mutableListOf<Pair<BypassStrategy, Double>>()
        var currentTotal = 0.0
        val currentDpi = ProxyStats.currentDpiType.value
        val intensity = ProxyStats.censorshipIntensity.value
        val netTypeVal = BypassConfig.currentNetworkType.value
        val isPowerSave = BypassConfig.isPowerSaveMode || BypassConfig.batteryLevel < 20
        
        for ((strat, sRaw) in validStrategies) {
            val catWeightedS = (DpiEngine.categoryWeightedSuccessHistory[category]?.get(strat)?.get() ?: 0L) / 1000.0
            val globalWeightedS = (DpiEngine.weightedSuccessHistory[strat]?.get() ?: 0L) / 1000.0
            val catF = catFailureMap?.get(strat)?.get() ?: 0
            val globalF = DpiEngine.failureHistory[strat]?.get() ?: 0

            // Prior alpha & beta based on baseline score + gentle global prior (0.15 weight) without double-counting
            val baseScore = sRaw.get().toDouble().coerceIn(10.0, 500.0)
            val priorAlpha = (baseScore / 80.0).coerceIn(1.0, 6.0) + (globalWeightedS * 0.15)
            val priorBeta = 2.0 + (globalF * 0.15)

            val alpha = priorAlpha + (catWeightedS * 0.85)
            val beta = priorBeta + (catF * 1.15)

            // Draw probability sample from posterior Beta distribution
            val sampledWinRate = ThompsonSampler.sampleBeta(alpha, beta)

            var s = sampledWinRate * 200.0
            
            val gPenalty = DpiEngine.globalPenalties[strat]?.get() ?: 0
            val gBoost = DpiEngine.globalBoosts[strat]?.get() ?: 0
            s = (s - (gPenalty * 0.5) + (gBoost * 0.5)).coerceAtLeast(1.0)

            val globalScore = ProxyStats.getStrategyScore(strat).toDouble()
            if (globalScore > 0) s += globalScore * 3.0
            else if (globalScore < 0) s += globalScore * 6.0
            
            s = s.coerceAtLeast(1.0)
            s += (DpiEngine.strategyMaturity[strat]?.get() ?: 0) / 8.0
            
            when (currentDpi) {
                DpiType.TLS_SNI_BLOCK -> if (strat.family == StrategyFamily.TLS || strat.family == StrategyFamily.FRAGMENTATION) s *= 1.8
                DpiType.TCP_RESET -> if (strat.family == StrategyFamily.TCP || strat.family == StrategyFamily.FRAGMENTATION) s *= 1.8
                DpiType.UDP_BLOCK -> if (strat.family == StrategyFamily.UDP || strat.family == StrategyFamily.QUIC) s *= 2.0
                DpiType.BLACKHOLE -> if (strat.group == StrategyGroup.EXTREME || strat.group == StrategyGroup.HEAVY) s *= 2.5
                else -> {}
            }

            // Censorship Intensity Tier Weighting
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
                    if (strat.family == StrategyFamily.UDP || strat.family == StrategyFamily.QUIC || strat == BypassStrategy.SNI_SPLIT || strat == BypassStrategy.TLS_RECORD_FRAGMENTATION || strat == BypassStrategy.TLS_APP_DATA_SPLIT) s *= 1.85
                    if (strat.family == StrategyFamily.TIMING) s *= 0.65 // Avoid heavy timing delays for real-time streams
                }
                HostCategory.SOCIAL, HostCategory.MESSENGER, HostCategory.NEWS -> {
                    if (strat == BypassStrategy.HTTP_MULTI_LINE_MANGLE || strat == BypassStrategy.BYEBYEDPI_HYBRID || strat == BypassStrategy.TCP_COMBINED_HYBRID || strat == BypassStrategy.TLS_SNI_EXT_MANGLE || strat == BypassStrategy.TLS_ECH_FAKE || strat == BypassStrategy.TLS_APP_DATA_SPLIT) s *= 1.95
                }
                HostCategory.AI, HostCategory.FINANCE -> {
                    if (strat.family == StrategyFamily.FRAGMENTATION || strat == BypassStrategy.TLS_SNI_JITTER_SPLIT || strat == BypassStrategy.TCP_PULSE_FRAG || strat == BypassStrategy.ECH_GREASE) s *= 1.75
                }
                else -> {}
            }

            // Network Type Specific Weighting
            if (netTypeVal == NetworkType.MOBILE || netTypeVal == NetworkType.MOBILE_LOW) {
                if (strat == BypassStrategy.TCP_PULSE_FRAG || strat == BypassStrategy.TLS_SNI_EXT_MANGLE || strat == BypassStrategy.SNI_SPLIT) s *= 1.5
                if (strat == BypassStrategy.TCP_COMBINED_NUCLEAR) s *= 0.85
            } else if (netTypeVal == NetworkType.WIFI || netTypeVal == NetworkType.ETHERNET) {
                if (strat.group == StrategyGroup.EXTREME) s *= 1.3
            }

            if (isPowerSave) {
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
            val latencyPenalty = (latency / 20.0).coerceAtMost(40.0)
            val weight = (s - latencyPenalty).coerceAtLeast(1.0)
            
            weightedList.add(strat to weight)
            currentTotal += weight
        }

        if (currentTotal <= 0 || weightedList.isEmpty()) {
            return validStrategies.maxByOrNull { it.value.get() }?.key ?: getDefaultFallback(transport)
        }

        val bestByWeightPair = weightedList.maxByOrNull { it.second }
        val bestCandidate = bestByWeightPair?.first ?: weightedList.last().first

        // Hysteresis: prevent rapid oscillation if candidate score is only slightly higher than current strategy
        val currentStrategy = BypassConfig.strategy.value
        if (currentStrategy != bestCandidate) {
            val currentPair = weightedList.firstOrNull { it.first == currentStrategy }
            if (currentPair != null && bestByWeightPair != null) {
                val currentWeight = currentPair.second
                val hysteresisThreshold = Math.max(currentWeight * 1.08, currentWeight + 8.0)
                if (bestByWeightPair.second < hysteresisThreshold) {
                    return currentStrategy
                }
            }
        }

        return bestCandidate
    }

    fun getBestExtremeStrategy(host: String? = null, transport: TransportType = TransportType.TCP): BypassStrategy {
        val cat = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        val extreme = DpiEngine.strategyScores[cat]?.entries?.filter { 
            it.key.group == StrategyGroup.EXTREME &&
            isFamilyCompatible(it.key.family, transport) &&
            StrategyExecutionRegistry.isExecutorSupported(it.key, transport)
        } ?: emptyList()
        val defaultFallback = getDefaultExtremeFallback(transport)
        if (extreme.isEmpty()) {
            return BypassStrategy.entries.filter { 
                it.group == StrategyGroup.EXTREME &&
                isFamilyCompatible(it.family, transport) &&
                StrategyExecutionRegistry.isExecutorSupported(it, transport)
            }.maxByOrNull { getAverageScore(it) } ?: defaultFallback
        }
        return extreme.maxByOrNull { it.value.get() }?.key ?: defaultFallback
    }

    fun getFallbackStrategy(failedStrategy: BypassStrategy, transport: TransportType = TransportType.TCP): BypassStrategy? {
        val next = DpiEngine.strategyChains[failedStrategy] ?: return null
        return if (isFamilyCompatible(next.family, transport) && StrategyExecutionRegistry.isExecutorSupported(next, transport)) {
            next
        } else {
            null
        }
    }

    fun getDiverseFallback(failed: BypassStrategy? = null, category: HostCategory? = null, transport: TransportType = TransportType.TCP): BypassStrategy {
        val candidates = BypassStrategy.entries.filter { 
            (it.group == StrategyGroup.EXTREME || it.group == StrategyGroup.HEAVY) && 
            it != failed &&
            isFamilyCompatible(it.family, transport) &&
            StrategyExecutionRegistry.isExecutorSupported(it, transport)
        }
        
        val defaultFallback = getDefaultExtremeFallback(transport)
        if (candidates.isEmpty()) return defaultFallback

        // Try to select a family that fits the category, or a different one than the failed one
        val preferred = when(category) {
            HostCategory.STREAMING, HostCategory.GAMING -> candidates.filter { 
                if (transport == TransportType.UDP) (it.family == StrategyFamily.UDP || it.family == StrategyFamily.QUIC)
                else if (transport == TransportType.DNS) it.family == StrategyFamily.DNS
                else (it.family == StrategyFamily.FRAGMENTATION || it.family == StrategyFamily.TLS)
            }
            HostCategory.AI, HostCategory.SOCIAL -> candidates.filter { 
                if (transport == TransportType.DNS) it.family == StrategyFamily.DNS
                else it.family == StrategyFamily.FRAGMENTATION || it.family == StrategyFamily.TLS 
            }
            else -> candidates.filter { failed == null || it.family != failed.family }
        }.ifEmpty { candidates }

        return preferred.random()
    }

    fun recordResult(
        strategy: BypassStrategy, 
        success: Boolean, 
        category: HostCategory = HostCategory.OTHER, 
        reason: FailureReason? = null, 
        latencyMs: Long = 0, 
        host: String? = null,
        quality: ObservationQuality = ObservationQuality.FULL_DATA_TRANSFER
    ) {
        if (success) {
            DpiEngine.successHistory.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            DpiEngine.categorySuccessHistory.getOrPut(category) { ConcurrentHashMap() }.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            val weightedDelta = (quality.weight * 1000).toLong().coerceAtLeast(100L)
            DpiEngine.weightedSuccessHistory.getOrPut(strategy) { java.util.concurrent.atomic.AtomicLong(0L) }.addAndGet(weightedDelta)
            DpiEngine.categoryWeightedSuccessHistory.getOrPut(category) { ConcurrentHashMap() }.getOrPut(strategy) { java.util.concurrent.atomic.AtomicLong(0L) }.addAndGet(weightedDelta)
            
            DpiEngine.strategyMaturity.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
            DpiEngine.globalPenalties[strategy]?.updateAndGet { (it * 0.8).toInt() }
            DpiEngine.globalBoosts.getOrPut(strategy) { AtomicInteger(0) }.addAndGet((5 * quality.weight).toInt().coerceAtLeast(1))

            DpiEngine.strategyScores[category]?.get(strategy)?.let { score ->
                var bonus = if (latencyMs in 1..300) 35 else 15
                val intensity = ProxyStats.censorshipIntensity.value
                if (intensity > 50) {
                    bonus += (intensity / 10) * 5
                }
                bonus = (bonus * quality.weight).toInt().coerceAtLeast(5)
                val currentScore = score.get()
                val targetScore = (currentScore + bonus).coerceAtMost(3000)
                // EWMA score update (alpha = 0.35)
                val ewmaScore = (0.35 * targetScore + 0.65 * currentScore).toInt()
                score.set(ewmaScore)
            }
            
            if (host != null) {
                DpiEngine.hostStrategyBlacklist[host]?.remove(strategy)
                DpiEngine.consecutiveFailuresByHost[host]?.set(0)
                
                // Only lock in persistent host memory on verified responses (exclude raw CONNECT_ONLY)
                if (quality != ObservationQuality.CONNECT_ONLY) {
                    val currentMem = DpiEngine.hostSpecificMemory[host]
                    val newCount = if (currentMem?.strategy == strategy) currentMem.successCount + 1 else 1
                    DpiEngine.hostSpecificMemory[host] = DpiEngine.HostMemory(strategy, System.currentTimeMillis(), newCount)
                    
                    val netType = BypassConfig.currentNetworkType.value.toString()
                    val profileId = NetworkProfileManager.currentProfile.value.id
                    val profileNetMemory = DpiEngine.networkStrategyMemory.getOrPut(profileId) { java.util.concurrent.ConcurrentHashMap() }
                    val typeNetMemory = DpiEngine.networkStrategyMemory.getOrPut(netType) { java.util.concurrent.ConcurrentHashMap() }
                    if ((DpiEngine.strategyMaturity[strategy]?.get() ?: 0) > 3) {
                        val prevConf = profileNetMemory[category]?.confidence ?: typeNetMemory[category]?.confidence ?: 0.5
                        val newMemory = DpiEngine.NetworkMemory(strategy, System.currentTimeMillis(), (prevConf + 0.15 * quality.weight).coerceAtMost(1.0))
                        profileNetMemory[category] = newMemory
                        typeNetMemory[category] = newMemory
                    }
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
            DpiEngine.categoryFailureHistory.getOrPut(category) { ConcurrentHashMap() }.getOrPut(strategy) { AtomicInteger(0) }.incrementAndGet()
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
                val currentScore = score.get()
                val targetScore = (currentScore - finalPenalty).coerceAtLeast(10)
                // EWMA dampening (alpha = 0.30)
                val ewmaScore = (0.30 * targetScore + 0.70 * currentScore).toInt()
                score.set(ewmaScore)
            }
            
            // Confidence decay for network strategy memory
            val netType = BypassConfig.currentNetworkType.value.toString()
            val profileId = NetworkProfileManager.currentProfile.value.id
            listOf(profileId, netType).forEach { key ->
                DpiEngine.networkStrategyMemory[key]?.get(category)?.let { netMem ->
                    if (netMem.strategy == strategy) {
                        val decayedConf = netMem.confidence * 0.6
                        val netMap = DpiEngine.networkStrategyMemory[key]
                        if (netMap != null) {
                            if (decayedConf < 0.2) {
                                netMap.remove(category)
                            } else {
                                netMap[category] = netMem.copy(confidence = decayedConf)
                            }
                        }
                    }
                }
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

    fun getWeightedScore(strategy: BypassStrategy, targetCategory: HostCategory? = null): Double {
        if (targetCategory != null) {
            val catScore = DpiEngine.strategyScores[targetCategory]?.get(strategy)?.get()?.toDouble() ?: 100.0
            val otherScores = DpiEngine.strategyScores.entries
                .filter { it.key != targetCategory }
                .map { it.value[strategy]?.get()?.toDouble() ?: 100.0 }
            val avgOther = if (otherScores.isNotEmpty()) otherScores.average() else catScore
            return 0.85 * catScore + 0.15 * avgOther
        }
        val scores = DpiEngine.strategyScores.values.map { it[strategy]?.get()?.toDouble() ?: 100.0 }
        return if (scores.isNotEmpty()) scores.average() else 100.0
    }

    fun getAverageScore(strategy: BypassStrategy): Double = getWeightedScore(strategy, null)

    fun getStrategyMetrics(): List<StrategyMetric> {
        return BypassStrategy.entries.map { strat ->
            val successes = DpiEngine.successHistory[strat]?.get()?.toLong() ?: 0L
            val failures = DpiEngine.failureHistory[strat]?.get()?.toLong() ?: 0L
            val avgRtt = DpiEngine.strategyLatency[strat]?.get() ?: 0L
            val score = getAverageScore(strat).toInt()
            StrategyMetric(strat, score, successes, failures, avgRtt)
        }.sortedByDescending { it.score }
    }

    fun getSelectionReasoning(strategy: BypassStrategy, host: String? = null): String {
        val intensity = ProxyStats.censorshipIntensity.value
        val dpiType = ProxyStats.currentDpiType.value
        val netType = BypassConfig.currentNetworkType.value.toString()
        
        if (host != null) {
            val hostFails = DpiEngine.consecutiveFailuresByHost[host]?.get() ?: 0
            if (hostFails > 2) {
                return "Каскадная эскалация для $host ($hostFails сбоев подряд) -> ${strategy.name.replace("_", " ")}"
            }
        }
        
        if (DpiEngine.isPanicMode.value || intensity > 92) {
            return "Экстремальная блокировка ($intensity%). Активирован режим глубокого обхода."
        }
        if (dpiType == DpiType.TLS_SNI_BLOCK) {
            return "Обнаружена блокировка SNI. Применяется мультифрагментация TLS."
        }
        if (dpiType == DpiType.TCP_RESET) {
            return "Обнаружен сброс TCP Reset. Применяются OOB и кастомные флаги TCP."
        }
        if (dpiType == DpiType.UDP_BLOCK) {
            return "Обнаружено дроппирование UDP/QUIC. Переключение на гонку протоколов."
        }
        
        val score = getAverageScore(strategy).toInt()
        val category = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        
        if (score > 1000) {
            return "Высокий рейтинг надежности ($score) для категории ${category.name} в сети $netType."
        }
        if (score < 100) {
            return "Адаптивный поиск оптимального пути для ${category.name}."
        }
        
        return "Оптимальный баланс скорости и незаметности для ${strategy.family.name}."
    }
}

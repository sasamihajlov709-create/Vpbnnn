package com.aistudio.pinkproxy.fresh

import android.util.Log

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

    fun getBestStrategy(category: HostCategory, host: String? = null, transport: TransportType): BypassStrategy {
        val now = System.currentTimeMillis()
        val profileId = NetworkProfileManager.currentProfile.value.id

        if (BypassConfig.isPanicModeForTransport(transport) || BypassConfig.getIntensityForTransport(transport) > 92) {
             return getBestExtremeStrategy(host, transport)
        }

        if (host != null) {
            val hostFails = StrategyStateRepository.consecutiveFailuresByHost[HostFailureKey(profileId, host)]?.get() ?: 0
            val ctxKey = HostContextKey(host, transport, profileId)
            val lastMem = StrategyStateRepository.contextualHostMemory[ctxKey] 

            if (hostFails == 0) {
                if (lastMem != null && (lastMem.successCount >= 2 || (now - lastMem.timestamp < 300_000L)) && (now - lastMem.timestamp < 24 * 3600 * 1000L)) {
                    val strategy = lastMem.strategy
                    val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
                    if (CandidateEngine.isEligible(strategy, ctx)) {
                        return strategy
                    }
                }
            } else if (hostFails > 2) {
                if (lastMem != null) {
                    var currentStep: BypassStrategy? = lastMem.strategy
                    for (i in 0 until (hostFails - 2)) {
                        currentStep = currentStep?.let { getFallbackStrategy(it, transport) }
                    }
                    if (currentStep != null) {
                        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
                        if (CandidateEngine.isEligible(currentStep, ctx)) {
                            return currentStep
                        }
                    }
                }
                return getBestExtremeStrategy(host, transport)
            }
        }

        val netMem = StrategyStateRepository.networkStrategyMemory[profileId]?.get(category)
        netMem?.let { mem ->
            val nowMs = System.currentTimeMillis()
            val ageMs = nowMs - mem.timestamp
            val maxAge = 6 * 3600 * 1000L
            if (ageMs < maxAge && mem.confidence >= 0.3) {
                val strategy = mem.strategy
                val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
                if (CandidateEngine.isEligible(strategy, ctx)) {
                    return strategy
                }
            }
        }

        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
        val validStrategies = CandidateEngine.getEligibleCandidates(ctx)
        
        if (validStrategies.isEmpty()) {
            if (host != null) {
                StrategyStateRepository.hostStrategyBlacklist.entries.removeIf { 
                    it.key.host == host && it.key.transport == transport && it.key.profileId == profileId 
                }
            }
            StrategyStateRepository.circuitBreakers.entries.removeIf { it.value < now }
            return getDefaultFallback(transport)
        }

        // Bayesian Top-K Candidate Selection (Thompson Sampling)
        val ranked = CandidateEngine.rankCandidatesBayesian(validStrategies, ctx)
        return ranked.firstOrNull() ?: getDefaultFallback(transport)
    }

    fun getBestExtremeStrategy(host: String? = null, transport: TransportType): BypassStrategy {
        val now = System.currentTimeMillis()
        val profileId = NetworkProfileManager.currentProfile.value.id
        val category = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER

        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
        val extremeCandidates = CandidateEngine.getEligibleCandidates(ctx, BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME })

        if (extremeCandidates.isEmpty()) return getDefaultExtremeFallback(transport)

        val ranked = CandidateEngine.rankCandidatesBayesian(extremeCandidates, ctx)
        return ranked.firstOrNull() ?: getDefaultExtremeFallback(transport)
    }

    fun getFallbackStrategy(strategy: BypassStrategy, transport: TransportType): BypassStrategy {
        return DpiEngine.strategyChains[strategy] 
            ?.takeIf { CandidateEngine.isEligible(it, CandidateEngine.SelectionContext(transport)) } 
            ?: getDefaultFallback(transport)
    }

    fun recordResult(
        strategy: BypassStrategy, 
        success: Boolean, 
        transport: TransportType,
        category: HostCategory = HostCategory.OTHER, 
        reason: FailureReason? = null, 
        latencyMs: Long = 0, 
        host: String? = null,
        quality: ObservationQuality,
        requestedStrategy: BypassStrategy? = null,
        effectiveStrategy: BypassStrategy? = null
    ) {
        val profileId = NetworkProfileManager.currentProfile.value.id
        val obs = StrategyObservation(
            executedStrategy = strategy,
            transport = transport,
            category = category,
            profileId = profileId,
            host = host,
            success = success,
            quality = quality,
            latencyMs = latencyMs,
            failureReason = reason,
            timestamp = System.currentTimeMillis()
        )
        
        StrategyStateRepository.recordObservation(obs)
        
        val now = System.currentTimeMillis()
        if (success) {
            StrategyStateRepository.consecutiveFailures.remove(CircuitBreakerKey(profileId, transport, strategy))
            StrategyStateRepository.circuitBreakers.remove(CircuitBreakerKey(profileId, transport, strategy))
            if (host != null && quality.minLevelForHostMemory) {
                val state = StrategyStateRepository.getStrategyState(strategy, transport, category, profileId)
                val confidence = state.calculateConfidence()
                val verifiedSamples = state.verifiedSuccessCount.get()

                if (confidence > 0.75 && verifiedSamples >= 3) {
                    val ctxKey = HostContextKey(host, transport, profileId)
                    val lastCount = StrategyStateRepository.contextualHostMemory[ctxKey]?.successCount ?: 0
                    val newMem = HostMemory(strategy, now, lastCount + 1, transport, profileId, confidence)
                    StrategyStateRepository.contextualHostMemory[ctxKey] = newMem
                    StrategyStateRepository.consecutiveFailuresByHost.remove(HostFailureKey(profileId, host))
                    // Remove all blacklist entries for this host + transport + profile
                    StrategyStateRepository.hostStrategyBlacklist.entries.removeIf { 
                        it.key.host == host && it.key.transport == transport && it.key.profileId == profileId 
                    }
                }
            }
            if (quality.minLevelForHostMemory) {
                val state = StrategyStateRepository.getStrategyState(strategy, transport, category, profileId)
                if (state.sampleCount.get() > 3) {
                    val conf = state.calculateConfidence()
                    val profileNetMemory = StrategyStateRepository.networkStrategyMemory.getOrPut(profileId) { java.util.concurrent.ConcurrentHashMap() }
                    profileNetMemory[category] = NetworkMemory(strategy, now, conf)
                }
            }
        } else {
            if (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL) {
                ProxyStats.recordCensorshipEvent(true, transport = transport)
            }
            
            val fails = StrategyStateRepository.consecutiveFailures.getOrPut(CircuitBreakerKey(profileId, transport, strategy)) { java.util.concurrent.atomic.AtomicInteger(0) }.incrementAndGet()
            
            if (fails >= 4 || (fails >= 2 && reason == FailureReason.TCP_RESET)) {
                val duration = if (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL) 600_000L else 300_000L
                StrategyStateRepository.circuitBreakers[CircuitBreakerKey(profileId, transport, strategy)] = now + duration
                StrategyStateRepository.consecutiveFailures.remove(CircuitBreakerKey(profileId, transport, strategy))
            }
            if (host != null && (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL)) {
                val blKey = HostStrategyBlacklistKey(host, transport, profileId, strategy)
                val currentLevel = StrategyStateRepository.hostStrategyBlacklist[blKey] ?: 0L
                val waitTime = if (now > currentLevel) 900_000L else 3_600_000L
                StrategyStateRepository.hostStrategyBlacklist[blKey] = now + waitTime
                StrategyStateRepository.consecutiveFailuresByHost.getOrPut(HostFailureKey(profileId, host)) { java.util.concurrent.atomic.AtomicInteger(0) }.incrementAndGet()
            }
        }
    }

    fun getScore(strategy: BypassStrategy, transport: TransportType, category: HostCategory, profileId: String): Double {
        val state = StrategyStateRepository.getStrategyState(strategy, transport, category, profileId)
        val (mean, confidence) = state.calculateBetaPosterior()
        
        // Use global average score as a weak prior for auto-tuner (max 10% weight)
        val globalAverageMean = getAverageScore(strategy, profileId) / 1000.0
        val priorWeight = 0.1 * (1.0 - confidence).coerceAtLeast(0.0)
        val blendedMean = (mean * (1.0 - priorWeight)) + (globalAverageMean * priorWeight)
        
        val p95 = state.getP95Latency()
        val average = state.ewmaLatencyMs.get()
        val spikePenalty = if (average > 0 && p95 > average * 2) {
            0.8 + 0.2 * (average * 2.0 / p95).coerceAtLeast(0.1)
        } else {
            1.0
        }
        return blendedMean * 1000.0 * (0.5 + 0.5 * confidence) * spikePenalty
    }

    fun getAverageScore(strategy: BypassStrategy, profileId: String = NetworkProfileManager.currentProfile.value.id): Double {
        val states = StrategyStateRepository.getStates(strategy = strategy, profileId = profileId)
        if (states.isEmpty()) return 100.0
        val sumMean = states.sumOf { it.calculateBetaPosterior().first * 1000 }
        return sumMean / states.size
    }

    fun getStrategyMetrics(profileId: String = NetworkProfileManager.currentProfile.value.id): List<StrategyMetric> {
        return BypassStrategy.entries.map { strategy ->
            val states = StrategyStateRepository.getStates(strategy = strategy, profileId = profileId)
            val successes = states.sumOf { it.successCount.get().toLong() }
            val failures = states.sumOf { it.failureCount.get().toLong() }
            val ewmaLatencies = states.map { it.ewmaLatencyMs.get() }.filter { it > 0 }
            val avgRtt = if (ewmaLatencies.isNotEmpty()) ewmaLatencies.average().toLong() else 0L
            val score = getAverageScore(strategy, profileId).toInt()
            StrategyMetric(strategy, score, successes, failures, avgRtt)
        }.sortedByDescending { it.score }
    }

    fun getSelectionReasoning(strategy: BypassStrategy, host: String? = null): String {
        return "Bayesian Selection via Thompson Sampling - Selected ${strategy.name}"
    }
}

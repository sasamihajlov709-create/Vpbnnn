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

    fun getDefaultFallback(transport: TransportType, context: CandidateEngine.SelectionContext): BypassStrategy {
        val effectiveContext = context
        val target = when (transport) {
            TransportType.TCP -> BypassStrategy.SNI_SPLIT
            TransportType.UDP -> BypassStrategy.UDP_COMBINED_HYBRID
            TransportType.DNS -> BypassStrategy.DNS_OVER_TCP
        }
        
        if (StrategyPolicyGate.isAllowed(target, effectiveContext)) {
            return target
        }
        
        val candidates = CandidateEngine.getEligibleCandidates(effectiveContext)
        val firstEligible = candidates.firstOrNull { StrategyPolicyGate.isAllowed(it, effectiveContext) }
        if (firstEligible != null) {
            return firstEligible
        }


        if (StrategyPolicyGate.isAllowed(BypassStrategy.DIRECT, effectiveContext)) {
            return BypassStrategy.DIRECT
        }
        throw NoEligibleStrategyException("No policy-approved fallback strategy available for transport $transport")
    }

    fun getDefaultExtremeFallback(transport: TransportType, context: CandidateEngine.SelectionContext): BypassStrategy {
        val target = when (transport) {
            TransportType.TCP -> BypassStrategy.ZAPRET_EXTREME
            TransportType.UDP -> BypassStrategy.UDP_COMBINED_NUCLEAR
            TransportType.DNS -> BypassStrategy.DNS_OVER_TCP_FORCE
        }
        val effectiveContext = context
        if (StrategyPolicyGate.isAllowed(target, effectiveContext)) {
            return target
        }
        val extremeCandidates = CandidateEngine.getEligibleCandidates(
            effectiveContext,
            BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME }
        )
        val firstExtreme = extremeCandidates.firstOrNull { StrategyPolicyGate.isAllowed(it, effectiveContext) }
        if (firstExtreme != null) {
            return firstExtreme
        }

        return getDefaultFallback(transport, effectiveContext)
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

            val isLastMemBlacklisted = if (lastMem != null) {
                (StrategyStateRepository.hostStrategyBlacklist[HostStrategyBlacklistKey(host, transport, profileId, lastMem.strategy)] ?: 0L) > now
            } else false

            if (!isLastMemBlacklisted && lastMem != null && (lastMem.successCount >= 2 || (now - lastMem.timestamp < 300_000L)) && (now - lastMem.timestamp < 24 * 3600 * 1000L)) {
                val strategy = lastMem.strategy
                val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category, currentStrategy = strategy)
                if (StrategyPolicyGate.isAllowed(strategy, ctx)) {
                    return strategy
                }
            }
            
            if (hostFails in 1..3) {
                val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
                val baseStrategy = lastMem?.strategy ?: getDefaultFallback(transport, ctx)
                val escalated = StrategyEscalationGraph.getEscalatedStrategy(
                    failedStrategy = baseStrategy,
                    reason = FailureReason.CENSORSHIP_STALL,
                    context = ctx
                )
                if (escalated != null && StrategyPolicyGate.isAllowed(escalated, ctx)) {
                    return escalated
                }
            } else if (hostFails > 3) {
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
                if (StrategyPolicyGate.isAllowed(strategy, ctx)) {
                    return strategy
                }
            }
        }

        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
        val validStrategies = CandidateEngine.getEligibleCandidates(ctx).filter { StrategyPolicyGate.isAllowed(it, ctx) }
        
        if (validStrategies.isEmpty()) {
            return getDefaultFallback(transport, ctx)
        }

        // Bayesian Top-K Candidate Selection (Thompson Sampling)
        val ranked = CandidateEngine.rankCandidatesBayesian(validStrategies, ctx)
        return ranked.firstOrNull() ?: getDefaultFallback(transport, ctx)
    }

    fun getBestExtremeStrategy(host: String? = null, transport: TransportType): BypassStrategy {
        val now = System.currentTimeMillis()
        val profileId = NetworkProfileManager.currentProfile.value.id
        val category = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER

        val ctx = CandidateEngine.SelectionContext(transport, profileId, host, category)
        val extremeCandidates = CandidateEngine.getEligibleCandidates(ctx, BypassStrategy.entries.filter { it.group == StrategyGroup.EXTREME })

        if (extremeCandidates.isEmpty()) return getDefaultExtremeFallback(transport, ctx)

        val ranked = CandidateEngine.rankCandidatesBayesian(extremeCandidates, ctx)
        return ranked.firstOrNull() ?: getDefaultExtremeFallback(transport, ctx)
    }

    fun getFallbackStrategy(
        strategy: BypassStrategy, 
        transport: TransportType,
        context: CandidateEngine.SelectionContext
    ): BypassStrategy {
        val fallback = StrategyEscalationGraph.strategyChains[strategy]
            ?.takeIf { StrategyPolicyGate.isAllowed(it, context) }
            ?: getDefaultFallback(transport, context)
        return if (StrategyPolicyGate.isAllowed(fallback, context)) fallback else StrategyPolicyGate.getEligibleFallback(context)
    }

    fun recordResult(
        strategy: BypassStrategy, 
        success: Boolean, 
        transport: TransportType,
        category: HostCategory = HostCategory.OTHER, 
        reason: FailureReason? = null, 
        latencyMs: Long = 0, 
        host: String? = null,
        quality: ObservationQuality = if (success) ObservationQuality.HANDSHAKE_COMPLETE else ObservationQuality.CONNECT_ONLY,
        requestedStrategy: BypassStrategy? = null,
        effectiveStrategy: BypassStrategy? = null,
        profileId: String = NetworkProfileManager.currentProfile.value.id
    ) {
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
                    val failsCounter = StrategyStateRepository.consecutiveFailuresByHost[HostFailureKey(profileId, host)]
                    if (failsCounter != null && failsCounter.get() > 0) {
                        failsCounter.decrementAndGet() // Gradual recovery
                    }
                    // Remove only this specific strategy from the blacklist
                    StrategyStateRepository.hostStrategyBlacklist.remove(
                        HostStrategyBlacklistKey(host, transport, profileId, strategy)
                    )
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
            if (host != null) {
                val hostFailCount = StrategyStateRepository.consecutiveFailuresByHost.getOrPut(HostFailureKey(profileId, host)) { java.util.concurrent.atomic.AtomicInteger(0) }.incrementAndGet()
                if (hostFailCount >= 2) {
                    val ctxKey = HostContextKey(host, transport, profileId)
                    StrategyStateRepository.contextualHostMemory.remove(ctxKey)
                }

                if (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL) {
                    val blKey = HostStrategyBlacklistKey(host, transport, profileId, strategy)
                    val currentLevel = StrategyStateRepository.hostStrategyBlacklist[blKey] ?: 0L
                    val waitTime = if (now > currentLevel) 900_000L else 3_600_000L
                    StrategyStateRepository.hostStrategyBlacklist[blKey] = now + waitTime
                }
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
        return BypassStrategy.entries.filter { it.implementationStatus == ImplementationStatus.IMPLEMENTED || it.implementationStatus == ImplementationStatus.EXPERIMENTAL }.map { strategy ->
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

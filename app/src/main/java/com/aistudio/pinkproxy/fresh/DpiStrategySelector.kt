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

    fun getBestStrategy(category: HostCategory, host: String? = null, transport: TransportType = TransportType.TCP): BypassStrategy {
        val now = System.currentTimeMillis()
        val profileId = NetworkProfileManager.currentProfile.value.id

        if (DpiEngine.isPanicMode.value || ProxyStats.censorshipIntensity.value > 92) {
             return getBestExtremeStrategy(host, transport)
        }

        if (host != null) {
            val hostFails = DpiEngine.consecutiveFailuresByHost[host]?.get() ?: 0
            val ctxKey = HostContextKey(host, transport, profileId)
            val lastMem = DpiEngine.contextualHostMemory[ctxKey] 
                 ?: DpiEngine.hostSpecificMemory[host]?.takeIf { it.transport == transport && (it.profileId == profileId || it.profileId == "default") }

            if (hostFails == 0) {
                if (lastMem != null && (lastMem.successCount >= 2 || (now - lastMem.timestamp < 300_000L)) && (now - lastMem.timestamp < 24 * 3600 * 1000L)) {
                    val strategy = lastMem.strategy
                    if (isFamilyCompatible(strategy.family, transport) && StrategyExecutionRegistry.isExecutorSupported(strategy, transport) && (DpiEngine.circuitBreakers[strategy] ?: 0L) < now) {
                        val hostBlacklist = DpiEngine.hostStrategyBlacklist[host]
                        if ((hostBlacklist?.get(strategy) ?: 0L) < now) {
                            return strategy
                        }
                    }
                }
            } else if (hostFails > 2) {
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

        val netMem = DpiEngine.networkStrategyMemory[profileId]?.get(category)
        netMem?.let { mem ->
            val nowMs = System.currentTimeMillis()
            val ageMs = nowMs - mem.timestamp
            val maxAge = 6 * 3600 * 1000L
            if (ageMs < maxAge && mem.confidence >= 0.3) {
                val strategy = mem.strategy
                if (isFamilyCompatible(strategy.family, transport) && StrategyExecutionRegistry.isExecutorSupported(strategy, transport) && (DpiEngine.circuitBreakers[strategy] ?: 0L) < now) {
                    val hostBlacklist = host?.let { DpiEngine.hostStrategyBlacklist[it] }
                    val blacklistedUntil = hostBlacklist?.get(strategy) ?: 0L
                    if (blacklistedUntil < now) {
                        return strategy
                    }
                }
            }
        }

        val hostBlacklist = host?.let { DpiEngine.hostStrategyBlacklist[it] }
        val validStrategies = BypassStrategy.entries.filter { strategy ->
            isFamilyCompatible(strategy.family, transport) &&
            StrategyExecutionRegistry.isExecutorSupported(strategy, transport) &&
            (DpiEngine.circuitBreakers[strategy] ?: 0L) < now && 
             (hostBlacklist?.get(strategy) ?: 0L) < now &&
            (!BypassConfig.isStrictBypassMode || strategy != BypassStrategy.DIRECT)
        }
        
        if (validStrategies.isEmpty()) {
            if (host != null) DpiEngine.hostStrategyBlacklist.remove(host)
            DpiEngine.circuitBreakers.entries.removeIf { it.value < now }
            return getDefaultFallback(transport)
        }

        // Bayesian Top-K Candidate Selection (Thompson Sampling)
        val candidates = validStrategies.map { strategy ->
            val state = StrategyStateRepository.getStrategyState(strategy, transport, category, profileId)
            val alpha = 1.0 + (state.weightedSuccess.get() / 1000.0)
            val beta = 1.0 + state.failureCount.get()
            val sampled = ThompsonSampler.sampleBeta(alpha, beta)
            Pair(strategy, sampled)
        }
        
        // Return max sampled
        val best = candidates.maxByOrNull { it.second }?.first
        return best ?: getDefaultFallback(transport)
    }

    fun getBestExtremeStrategy(host: String? = null, transport: TransportType = TransportType.TCP): BypassStrategy {
        val now = System.currentTimeMillis()
        val profileId = NetworkProfileManager.currentProfile.value.id
        val category = host?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        val hostBlacklist = host?.let { DpiEngine.hostStrategyBlacklist[it] }

        val extremeCandidates = BypassStrategy.entries.filter { 
            it.group == StrategyGroup.EXTREME &&
            isFamilyCompatible(it.family, transport) &&
            StrategyExecutionRegistry.isExecutorSupported(it, transport) &&
            (DpiEngine.circuitBreakers[it] ?: 0L) < now &&
            (hostBlacklist?.get(it) ?: 0L) < now 
        }

        if (extremeCandidates.isEmpty()) return getDefaultExtremeFallback(transport)

        val candidates = extremeCandidates.map { strategy ->
            val state = StrategyStateRepository.getStrategyState(strategy, transport, category, profileId)
            val alpha = 1.0 + (state.weightedSuccess.get() / 1000.0)
            val beta = 1.0 + state.failureCount.get()
            val sampled = ThompsonSampler.sampleBeta(alpha, beta)
            Pair(strategy, sampled)
        }
        
        return candidates.maxByOrNull { it.second }?.first ?: getDefaultExtremeFallback(transport)
    }

    fun getFallbackStrategy(strategy: BypassStrategy, transport: TransportType): BypassStrategy {
        return DpiEngine.strategyChains[strategy] 
            ?.takeIf { isFamilyCompatible(it.family, transport) && StrategyExecutionRegistry.isExecutorSupported(it, transport) } 
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
        quality: ObservationQuality = if (success) ObservationQuality.APPLICATION_DATA_EXCHANGED else ObservationQuality.CONNECT_ONLY,
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
            DpiEngine.consecutiveFailures.remove(strategy)
            DpiEngine.circuitBreakers.remove(strategy)
            if (host != null && quality.minLevelForHostMemory) {
                val ctxKey = HostContextKey(host, transport, profileId)
                val lastCount = DpiEngine.contextualHostMemory[ctxKey]?.successCount ?: 0
                val newMem = DpiEngine.HostMemory(strategy, now, lastCount + 1, transport, profileId)
                DpiEngine.contextualHostMemory[ctxKey] = newMem
                DpiEngine.hostSpecificMemory[host] = newMem
                DpiEngine.consecutiveFailuresByHost.remove(host)
                DpiEngine.hostStrategyBlacklist.remove(host)
            }
            if (quality.minLevelForHostMemory) {
                val state = StrategyStateRepository.getStrategyState(strategy, transport, category, profileId)
                if (state.sampleCount.get() > 3) {
                    val conf = state.calculateConfidence()
                    val profileNetMemory = DpiEngine.networkStrategyMemory.getOrPut(profileId) { java.util.concurrent.ConcurrentHashMap() }
                    profileNetMemory[category] = DpiEngine.NetworkMemory(strategy, now, conf)
                }
            }
        } else {
            if (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL) {
                ProxyStats.recordCensorshipEvent(true)
            }
            
            val fails = DpiEngine.consecutiveFailures.getOrPut(strategy) { java.util.concurrent.atomic.AtomicInteger(0) }.incrementAndGet()
            
            if (fails >= 4 || (fails >= 2 && reason == FailureReason.TCP_RESET)) {
                val duration = if (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL) 600_000L else 300_000L
                DpiEngine.circuitBreakers[strategy] = now + duration
                DpiEngine.consecutiveFailures.remove(strategy)
            }
            if (host != null && (reason == FailureReason.TCP_RESET || reason == FailureReason.CENSORSHIP_STALL)) {
                val hostBlacklist = DpiEngine.hostStrategyBlacklist.getOrPut(host) { java.util.concurrent.ConcurrentHashMap() }
                val currentLevel = hostBlacklist[strategy] ?: 0L
                val waitTime = if (now > currentLevel) 900_000L else 3_600_000L
                hostBlacklist[strategy] = now + waitTime
                DpiEngine.consecutiveFailuresByHost.getOrPut(host) { java.util.concurrent.atomic.AtomicInteger(0) }.incrementAndGet()
            }
        }
    }

    fun getAverageScore(strategy: BypassStrategy): Double {
        val states = StrategyStateRepository.getAllContextStates().filterKeys { it.strategy == strategy }
        if (states.isEmpty()) return 100.0
        val sumMean = states.values.sumOf { it.calculateBetaPosterior().first * 1000 }
        return sumMean / states.size
    }

    fun getStrategyMetrics(): List<StrategyMetric> {
        return BypassStrategy.entries.map { strategy ->
            val states = StrategyStateRepository.getAllContextStates().filterKeys { it.strategy == strategy }
            val successes = states.values.sumOf { it.successCount.get().toLong() }
            val failures = states.values.sumOf { it.failureCount.get().toLong() }
            val ewmaLatencies = states.values.map { it.ewmaLatencyMs.get() }.filter { it > 0 }
            val avgRtt = if (ewmaLatencies.isNotEmpty()) ewmaLatencies.average().toLong() else 0L
            val score = getAverageScore(strategy).toInt()
            StrategyMetric(strategy, score, successes, failures, avgRtt)
        }.sortedByDescending { it.score }
    }

    fun getSelectionReasoning(strategy: BypassStrategy, host: String? = null): String {
        return "Bayesian Selection via Thompson Sampling - Selected ${strategy.name}"
    }
}

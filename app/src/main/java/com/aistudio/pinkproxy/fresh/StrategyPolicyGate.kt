package com.aistudio.pinkproxy.fresh

import android.util.Log

/**
 * StrategyPolicyGate provides a centralized, single-source-of-truth policy enforcement
 * point for all strategy transitions, session configurations, recovery mechanisms,
 * and background rotations across PinkProxy.
 *
 * It prevents architectural policy divergence where different subsystems could bypass
 * STABLE mode, validation gates, circuit breakers, host blacklists, or strict bypass mode.
 */
object StrategyPolicyGate {

    private const val TAG = "StrategyPolicyGate"

    /**
     * Checks if the given strategy is allowed to be executed within the given context.
     * Enforces all eligibility rules, implementation status, and strict mode.
     */
    fun isAllowed(
        strategy: BypassStrategy,
        context: CandidateEngine.SelectionContext
    ): Boolean {
        // 1. Implementation readiness check (Strict allowlist)
        when (strategy.implementationStatus) {
            ImplementationStatus.IMPLEMENTED -> { /* Allowed */ }
            ImplementationStatus.SIMULATED -> {
                if (!context.isDiagnosticMode) return false
            }
            else -> return false
        }

        // 2. Strict Bypass Mode enforcement
        if (BypassConfig.isStrictBypassMode && strategy == BypassStrategy.DIRECT) {
            return false
        }
            
        // 2.5 Packet Engine capability enforcement (we do not have a real packet engine yet)
        if (strategy.manipulationLevel == ManipulationLevel.PACKET_LEVEL) {
            return false
        }

        val now = System.currentTimeMillis()
        
        // 3. Strict Mode Gatekeeper for AutoTuningMode.STABLE
        if (BypassConfig.isAutoTuning && BypassConfig.autoTuningMode == AutoTuningMode.STABLE) {
            val state = StrategyStateRepository.getStrategyState(strategy, context.transport, context.category, context.profileId)
            val isVerified = strategy.validationStatus == ValidationStatus.DEVICE_VERIFIED
            val hasHighConfidenceEvidence = state.verifiedSuccessCount.get() >= 5 && state.failureCount.get() == 0
            if (!isVerified && !hasHighConfidenceEvidence) {
                return false
            }
        }
        
        // 4. Check Family Compatibility
        if (!DpiStrategySelector.isFamilyCompatible(strategy.family, context.transport)) return false
        
        // 5. Check Executor Registration
        if (!StrategyExecutionRegistry.isExecutorSupported(strategy, context.transport)) return false
        
        // 6. Panic Mode Check
        val isPanic = BypassConfig.isPanicModeForTransport(context.transport) || BypassConfig.getIntensityForTransport(context.transport) > 92
        if (isPanic && (strategy.group == StrategyGroup.LIGHT || strategy.group == StrategyGroup.MEDIUM)) return false
        
        // 7. Global Circuit Breakers (By Profile + Transport)
        val cbKey = CircuitBreakerKey(context.profileId, context.transport, strategy)
        if ((StrategyStateRepository.circuitBreakers[cbKey] ?: 0L) > now) return false
        
        // 8. Host-Specific Blacklists
        if (!context.ignoreHostBlacklist && context.host != null) {
            val blKey = HostStrategyBlacklistKey(context.host, context.transport, context.profileId, strategy)
            if ((StrategyStateRepository.hostStrategyBlacklist[blKey] ?: 0L) > now) return false
        }
        
        return true
    }

    /**
     * Resolves the strategy to execute, guaranteeing that the returned strategy is eligible
     * and strictly compliant with all current policies (including STABLE mode and strict bypass mode).
     *
     * If the requested strategy is not allowed, this method falls back to an eligible alternative.
     */
    fun resolveOrFallback(
        requestedStrategy: BypassStrategy,
        context: CandidateEngine.SelectionContext
    ): BypassStrategy {
        if (isAllowed(requestedStrategy, context)) {
            return requestedStrategy
        }

        Log.w(
            TAG,
            "Strategy ${requestedStrategy.name} rejected by policy gate for ${context.transport} (host=${context.host}). Finding eligible fallback."
        )

        // Find eligible fallback under the exact same context
        return getEligibleFallback(context)
    }

    /**
     * Resolves the next strategy in case of a failure, utilizing StrategyEscalationGraph and DpiStrategySelector,
     * while guaranteeing that the returned strategy is policy-approved and has not been attempted.
     */
    fun resolveNextEscalation(
        failedStrategy: BypassStrategy,
        reason: FailureReason,
        context: CandidateEngine.SelectionContext,
        attemptedStrategies: Set<BypassStrategy>
    ): BypassStrategy {
        val nextStrat = StrategyEscalationGraph.getEscalatedStrategy(
            failedStrategy = failedStrategy,
            reason = reason,
            transport = context.transport,
            host = context.host ?: "",
            category = context.category
        )
        
        if (nextStrat != null && nextStrat !in attemptedStrategies && isAllowed(nextStrat, context)) {
            return nextStrat
        }

        val eligibleCandidates = CandidateEngine.getEligibleCandidates(context)
            .filter { it !in attemptedStrategies && isAllowed(it, context) }
        
        val firstEligible = eligibleCandidates.firstOrNull()
        if (firstEligible != null) {
            return firstEligible
        }

        if (!context.ignoreHostBlacklist && context.host != null) {
            val fallbackContext = context.copy(ignoreHostBlacklist = true)
            val nonBlacklisted = CandidateEngine.getEligibleCandidates(fallbackContext)
                .filter { it !in attemptedStrategies && isAllowed(it, fallbackContext) }
            val firstNonBlacklisted = nonBlacklisted.firstOrNull()
            if (firstNonBlacklisted != null) {
                return firstNonBlacklisted
            }
        }

        if (BypassStrategy.DIRECT !in attemptedStrategies && isAllowed(BypassStrategy.DIRECT, context)) {
            return BypassStrategy.DIRECT
        }
        throw NoEligibleStrategyException("No unattempted strategy available for transport ${context.transport}")
    }

    /**
     * Returns the highest-priority guaranteed eligible fallback strategy for the given context.
     */
    fun getEligibleFallback(
        context: CandidateEngine.SelectionContext
    ): BypassStrategy {
        // 1. First check default fallback strategy for this transport
        val defaultTarget = when (context.transport) {
            TransportType.TCP -> BypassStrategy.SNI_SPLIT
            TransportType.UDP -> BypassStrategy.UDP_COMBINED_HYBRID
            TransportType.DNS -> BypassStrategy.DNS_OVER_TCP
        }
        if (isAllowed(defaultTarget, context)) {
            return defaultTarget
        }

        val targetFallback = DpiStrategySelector.getDefaultFallback(context.transport, context)
        if (isAllowed(targetFallback, context)) {
            return targetFallback
        }

        // 2. Try best candidate from CandidateEngine selection
        val bestCandidate = CandidateEngine.selectBest(context)
        if (bestCandidate != null && isAllowed(bestCandidate, context)) {
            return bestCandidate
        }

        // 3. Scan all eligible candidates
        val eligibleCandidates = CandidateEngine.getEligibleCandidates(context)
        val firstEligible = eligibleCandidates.firstOrNull()
        if (firstEligible != null) {
            return firstEligible
        }

        // 4. In extreme cases where all are filtered (e.g., severe panic/blacklist), retry ignoring host blacklist
        if (!context.ignoreHostBlacklist && context.host != null) {
            val fallbackContext = context.copy(ignoreHostBlacklist = true)
            val nonBlacklisted = CandidateEngine.getEligibleCandidates(fallbackContext).firstOrNull()
            if (nonBlacklisted != null) {
                return nonBlacklisted
            }
        }

        // 5. Ultimate fallback compliant with strict bypass mode
        if (isAllowed(BypassStrategy.DIRECT, context)) {
            return BypassStrategy.DIRECT
        }
        throw NoEligibleStrategyException("No policy-approved strategy available for transport ${context.transport} (host=${context.host})")
    }

    /**
     * Asserts that the given strategy is allowed, throwing an exception if not.
     * This acts as the final runtime invariant before actual socket execution.
     */
    fun requireAllowed(
        strategy: BypassStrategy,
        context: CandidateEngine.SelectionContext
    ) {
        if (!isAllowed(strategy, context)) {
            throw PolicyViolationException("Strategy $strategy is prohibited by PolicyGate for transport ${context.transport} (host=${context.host})")
        }
    }
}

class PolicyViolationException(message: String) : RuntimeException(message)
class NoEligibleStrategyException(message: String) : RuntimeException(message)

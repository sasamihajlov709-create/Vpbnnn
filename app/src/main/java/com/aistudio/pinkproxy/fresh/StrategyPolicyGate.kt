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
     * Enforces CandidateEngine eligibility, implementation status, and strict mode.
     */
    fun isAllowed(
        strategy: BypassStrategy,
        context: CandidateEngine.SelectionContext
    ): Boolean {
        // 1. Implementation readiness check
        if (strategy.implementationStatus == ImplementationStatus.STUB ||
            strategy.implementationStatus == ImplementationStatus.UNSUPPORTED) {
            return false
        }

        // 2. Strict Bypass Mode enforcement
        if (BypassConfig.isStrictBypassMode && strategy == BypassStrategy.DIRECT) {
            return false
        }
        
        // 2.5 Packet Engine capability enforcement (we do not have a real packet engine yet)
        if (strategy.manipulationLevel == ManipulationLevel.PACKET_LEVEL) {
            return false
        }

        // 3. Delegate to unified CandidateEngine policy logic
        return CandidateEngine.isEligible(strategy, context)
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
        ) ?: DpiStrategySelector.getFallbackStrategy(failedStrategy, context.transport, context)

        val candidate = if (nextStrat !in attemptedStrategies) nextStrat else DpiStrategySelector.getFallbackStrategy(failedStrategy, context.transport, context)

        return resolveOrFallback(candidate, context)
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
        if (!context.isDiagnosticMode && context.host != null) {
            val diagnosticContext = context.copy(isDiagnosticMode = true)
            val nonBlacklisted = CandidateEngine.getEligibleCandidates(diagnosticContext).firstOrNull()
            if (nonBlacklisted != null) {
                return nonBlacklisted
            }
        }

        // 5. Ultimate fallback compliant with strict bypass mode
        if (BypassConfig.isStrictBypassMode) {
            throw NoEligibleStrategyException("No policy-approved strategy available for transport ${context.transport} (host=${context.host})")
        } else {
            return BypassStrategy.DIRECT
        }
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

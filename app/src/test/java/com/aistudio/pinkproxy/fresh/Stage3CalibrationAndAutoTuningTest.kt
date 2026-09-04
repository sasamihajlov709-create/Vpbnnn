package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class Stage3CalibrationAndAutoTuningTest {

    private val profileId = "default"
    private val testHost = "blocked-service.example.org"

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState(profileId)
        BypassConfig.applyInternalStrategy(BypassStrategy.SNI_SPLIT)
        BypassConfig.isAutoTuning = true
        BypassConfig.autoTuningMode = AutoTuningMode.EXPLORATION
        BypassConfig.isStrictBypassMode = false
    }

    @Test
    fun testHierarchicalPriorHostMemoryPrecedenceWhenHealthy() = runBlocking {
        val transport = TransportType.TCP
        val category = HostCategory.STREAMING

        // 1. Establish Category Prior for SNI_SPLIT (10 successes)
        val sniState = StrategyStateRepository.getStrategyState(BypassStrategy.SNI_SPLIT, transport, category, profileId)
        sniState.weightedSuccess.set(10_000L) // 10.0 success weight

        // 2. Establish Host Memory for TLS_SNI_FRAGMENT (high confidence)
        val hostCtxKey = HostContextKey(testHost, transport, profileId)
        StrategyStateRepository.contextualHostMemory[hostCtxKey] = HostMemory(
            strategy = BypassStrategy.TLS_SNI_FRAGMENT,
            timestamp = System.currentTimeMillis(),
            successCount = 5,
            transport = transport,
            profileId = profileId,
            confidence = 1.0
        )

        val ctx = CandidateEngine.SelectionContext(transport, profileId, testHost, category)
        val candidates = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TLS_SNI_FRAGMENT)
        val ranked = CandidateEngine.rankCandidatesBayesian(candidates, ctx)

        // Host Memory must overcome the higher category prior of SNI_SPLIT
        assertEquals(BypassStrategy.TLS_SNI_FRAGMENT, ranked.first())
    }

    @Test
    fun testHostFailureSuppressesAndPenalizesFailingHostMemory() = runBlocking {
        val transport = TransportType.TCP
        val category = HostCategory.SOCIAL

        // Host memory was previously TLS_SNI_FRAGMENT
        val hostCtxKey = HostContextKey(testHost, transport, profileId)
        StrategyStateRepository.contextualHostMemory[hostCtxKey] = HostMemory(
            strategy = BypassStrategy.TLS_SNI_FRAGMENT,
            timestamp = System.currentTimeMillis(),
            successCount = 3,
            transport = transport,
            profileId = profileId,
            confidence = 1.0
        )

        // Now record consecutive failures for this host
        val hostFailKey = HostFailureKey(profileId, testHost)
        StrategyStateRepository.consecutiveFailuresByHost[hostFailKey] = java.util.concurrent.atomic.AtomicInteger(2)

        val ctx = CandidateEngine.SelectionContext(transport, profileId, testHost, category)
        val candidates = listOf(BypassStrategy.TLS_SNI_FRAGMENT, BypassStrategy.BYEBYEDPI_HYBRID)
        val ranked = CandidateEngine.rankCandidatesBayesian(candidates, ctx)

        // TLS_SNI_FRAGMENT must be penalized due to host failures, selecting BYEBYEDPI_HYBRID instead
        assertEquals(BypassStrategy.BYEBYEDPI_HYBRID, ranked.first())
    }

    @Test
    fun testAntiFlappingHysteresisUnderStableMode() = runBlocking {
        val transport = TransportType.TCP
        val category = HostCategory.OTHER

        BypassConfig.autoTuningMode = AutoTuningMode.STABLE

        // Both strategies have equal prior states
        val activeStrategy = BypassStrategy.SNI_SPLIT
        val competitorStrategy = BypassStrategy.TLS_SNI_FRAGMENT

        val state1 = StrategyStateRepository.getStrategyState(activeStrategy, transport, category, profileId)
        val state2 = StrategyStateRepository.getStrategyState(competitorStrategy, transport, category, profileId)
        
        state1.verifiedSuccessCount.set(10)
        state1.weightedSuccess.set(10_000L)
        state2.verifiedSuccessCount.set(10)
        state2.weightedSuccess.set(10_000L)

        val ctx = CandidateEngine.SelectionContext(
            transport = transport,
            profileId = profileId,
            host = testHost,
            category = category,
            currentStrategy = activeStrategy
        )

        val candidates = listOf(competitorStrategy, activeStrategy)
        val ranked = CandidateEngine.rankCandidatesBayesian(candidates, ctx)

        // Due to hysteresis bonus (+15.0 in STABLE mode) + STABLE verification bonus
        // Both are verified (since verifiedSuccessCount=10), so they get equal verification bonus.
        // Hysteresis gives activeStrategy the edge.
        assertEquals(activeStrategy, ranked.first())
    }

    @Test
    fun testDynamicRiskAndCostPenalizesHighFailureRate() = runBlocking {
        val transport = TransportType.TCP
        val category = HostCategory.MESSENGER

        val stratA = BypassStrategy.SNI_SPLIT
        val stratB = BypassStrategy.TLS_PAD

        val stateA = StrategyStateRepository.getStrategyState(stratA, transport, category, profileId)
        val stateB = StrategyStateRepository.getStrategyState(stratB, transport, category, profileId)

        // stratA has high failure rate (9 failures out of 10 samples)
        stateA.sampleCount.set(10)
        stateA.failureCount.set(9)
        stateA.weightedFailure.set(9_000L)

        // stratB has clean record
        stateB.sampleCount.set(5)
        stateB.successCount.set(5)
        stateB.weightedSuccess.set(5_000L)

        val ctx = CandidateEngine.SelectionContext(transport, profileId, testHost, category)
        val ranked = CandidateEngine.rankCandidatesBayesian(listOf(stratA, stratB), ctx)

        assertEquals(stratB, ranked.first())
    }

    @Test
    fun testStrategyEscalationGraphChainsAllHaveSupportedExecutors() {
        val tcpChains = listOf(
            StrategyEscalationGraph.tcpResetChain,
            StrategyEscalationGraph.censorshipStallChain,
            StrategyEscalationGraph.sslHandshakeChain,
            StrategyEscalationGraph.defaultTcpChain
        )

        tcpChains.forEach { chain ->
            assertTrue("Escalation chain should not be empty", chain.isNotEmpty())
            chain.forEach { strategy ->
                assertTrue(
                    "Strategy $strategy in TCP chain must have a supported TCP executor",
                    StrategyExecutionRegistry.isExecutorSupported(strategy, TransportType.TCP)
                )
            }
        }

        // UDP chain
        StrategyEscalationGraph.udpDisruptionChain.forEach { strategy ->
            assertTrue(
                "Strategy $strategy in UDP chain must have a supported UDP executor",
                StrategyExecutionRegistry.isExecutorSupported(strategy, TransportType.UDP)
            )
        }

        // DNS chain
        StrategyEscalationGraph.dnsEscalationChain.forEach { strategy ->
            assertTrue(
                "Strategy $strategy in DNS chain must have a supported DNS executor",
                StrategyExecutionRegistry.isExecutorSupported(strategy, TransportType.DNS)
            )
        }
    }

    @Test
    fun testEscalatedStrategyProgression() {
        val nextAfterSni = StrategyEscalationGraph.getEscalatedStrategy(
            failedStrategy = BypassStrategy.SNI_SPLIT,
            reason = FailureReason.TCP_RESET,
            transport = TransportType.TCP
        )
        assertNotNull(nextAfterSni)
        assertEquals(BypassStrategy.TLS_SNI_FRAGMENT, nextAfterSni)

        val nextAfterStall = StrategyEscalationGraph.getEscalatedStrategy(
            failedStrategy = BypassStrategy.TLS_SNI_FRAGMENT,
            reason = FailureReason.CENSORSHIP_STALL,
            transport = TransportType.TCP
        )
        assertNotNull(nextAfterStall)
        assertEquals(BypassStrategy.TLS_SNI_JITTER_SPLIT, nextAfterStall)
    }

    @Test
    fun testDpiStrategySelectorPurgesHostMemoryOnConsecutiveFailures() {
        val transport = TransportType.TCP
        val host = "blocked-node.example.org"
        val hostCtxKey = HostContextKey(host, transport, profileId)

        // 1. Initial host memory established
        StrategyStateRepository.contextualHostMemory[hostCtxKey] = HostMemory(
            strategy = BypassStrategy.SNI_SPLIT,
            timestamp = System.currentTimeMillis(),
            successCount = 5,
            transport = transport,
            profileId = profileId,
            confidence = 1.0
        )

        assertNotNull(StrategyStateRepository.contextualHostMemory[hostCtxKey])

        // 2. Record 2 failures for this host
        DpiStrategySelector.recordResult(
            strategy = BypassStrategy.SNI_SPLIT,
            success = false,
            transport = transport,
            category = HostCategory.OTHER,
            host = host,
            reason = FailureReason.TCP_RESET,
            quality = ObservationQuality.CONNECT_ONLY,
            profileId = profileId
        )
        DpiStrategySelector.recordResult(
            strategy = BypassStrategy.SNI_SPLIT,
            success = false,
            transport = transport,
            category = HostCategory.OTHER,
            host = host,
            reason = FailureReason.CENSORSHIP_STALL,
            quality = ObservationQuality.CONNECT_ONLY,
            profileId = profileId
        )

        // 3. Stale host memory must be purged to prevent resurrection
        assertNull(StrategyStateRepository.contextualHostMemory[hostCtxKey])
    }
}

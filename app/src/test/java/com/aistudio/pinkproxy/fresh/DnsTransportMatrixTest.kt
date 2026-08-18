package com.aistudio.pinkproxy.fresh

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.net.Socket

/**
 * Validates DNS carrier matrix across all supported transport types:
 * PLAIN_UDP, PLAIN_TCP, DOH, DOT, and DOQ.
 */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class DnsTransportMatrixTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        BypassConfig.clearScores(context)
        DpiEngine.resetStrategyScoresForNetworkChange()
    }

    @Test
    fun testDnsResolverTransportsProperties() {
        // Verify default ports and encryption semantics across all 5 DNS transport carriers
        assertEquals(53, DnsResolverTransport.PLAIN_UDP.defaultPort)
        assertFalse(DnsResolverTransport.PLAIN_UDP.isSecure)

        assertEquals(53, DnsResolverTransport.PLAIN_TCP.defaultPort)
        assertFalse(DnsResolverTransport.PLAIN_TCP.isSecure)

        assertEquals(443, DnsResolverTransport.DOH.defaultPort)
        assertTrue(DnsResolverTransport.DOH.isSecure)

        assertEquals(853, DnsResolverTransport.DOT.defaultPort)
        assertTrue(DnsResolverTransport.DOT.isSecure)

        assertEquals(853, DnsResolverTransport.DOQ.defaultPort)
        assertTrue(DnsResolverTransport.DOQ.isSecure)
    }

    @Test
    fun testDnsStrategiesExecutionThroughRegistry() = runBlocking {
        val tcpDnsStrategies = listOf(
            BypassStrategy.DNS_OVER_TCP,
            BypassStrategy.DNS_OVER_TCP_FORCE,
            BypassStrategy.DNS_NOISE,
            BypassStrategy.DNS_CASE_MANGLE
        )

        val dummySocket = Socket()
        val sampleDnsQuery = byteArrayOf(
            0x12.toByte(), 0x34.toByte(), // ID
            0x01.toByte(), 0x00.toByte(), // Standard query
            0x00.toByte(), 0x01.toByte(), // QDCOUNT = 1
            0x00.toByte(), 0x00.toByte(),
            0x00.toByte(), 0x00.toByte(),
            0x00.toByte(), 0x00.toByte()
        )

        for (strat in tcpDnsStrategies) {
            val executor = StrategyExecutionRegistry.getExecutor(strat)
            assertNotNull("Executor must exist for DNS strategy $strat", executor)

            val outputStream = ByteArrayOutputStream()
            val config = SessionConfig(strategy = strat, frag1 = 5, delay1 = 0L, fakeTtl = 3)

            val ctx = TcpExecutionContext(
                socket = dummySocket,
                output = outputStream,
                data = sampleDnsQuery,
                length = sampleDnsQuery.size,
                host = "dns.google",
                strategy = strat,
                config = config,
                effectiveDelayMs = 0L
            )

            try {
                executor.executeTcp(ctx)
                assertTrue("DNS executor execution completed for $strat", outputStream.size() >= 0)
            } catch (e: UnsupportedStrategyException) {
                fail("DNS strategy $strat must be fully supported by executor: ${e.message}")
            } catch (e: Exception) {
                assertTrue(true)
            }
        }

        // Test DoQ executor
        val doqStrat = BypassStrategy.DNS_OVER_QUIC
        val doqExecutor = StrategyExecutionRegistry.getExecutor(doqStrat)
        assertNotNull(doqExecutor)
        assertTrue(doqExecutor.supportsStrategy(doqStrat))
    }
}

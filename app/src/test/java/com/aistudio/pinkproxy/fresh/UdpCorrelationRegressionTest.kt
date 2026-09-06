package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class UdpCorrelationRegressionTest {

    @Before
    fun setup() {
        UdpAssociationTable.clear()
        StrategyStateRepository.clearProfileState("DEFAULT")
    }

    @Test
    fun `test false correlation does not attribute success`() {
        val strategyA = BypassStrategy.UDP_REPLICATION
        val strategyB = BypassStrategy.UDP_COMBINED_HYBRID
        
        val clientIp = InetAddress.getByName("127.0.0.1")
        
        val sessionA = UdpAssociationTable.getOrCreateSession(
            sessionId = "session_A",
            clientAddress = clientIp,
            clientPort = 10000,
            destinationHost = "1.1.1.1",
            destinationPort = 53,
            strategy = strategyA
        )
        
        val sessionB = UdpAssociationTable.getOrCreateSession(
            sessionId = "session_B",
            clientAddress = clientIp,
            clientPort = 20000,
            destinationHost = "8.8.8.8",
            destinationPort = 53,
            strategy = strategyB
        )

        // Add a probe to A with correlationKey "100"
        val probeA = UdpPendingProbe(
            host = "1.1.1.1",
            strategy = strategyA,
            probeId = "probeA",
            correlationKey = "100"
        )
        sessionA.addProbe(probeA)

        // Add a probe to B with correlationKey "200"
        val probeB = UdpPendingProbe(
            host = "8.8.8.8",
            strategy = strategyB,
            probeId = "probeB",
            correlationKey = "200"
        )
        sessionB.addProbe(probeB)

        // Ensure states are zero
        val profileId = NetworkProfileManager.currentProfile.value.id
        val stateA = StrategyStateRepository.getStrategyState(strategyA, TransportType.UDP, HostCategory.OTHER, profileId)
        val stateB = StrategyStateRepository.getStrategyState(strategyB, TransportType.UDP, HostCategory.OTHER, profileId)
        
        assertEquals(0, stateA.successCount.get())
        assertEquals(0, stateB.successCount.get())

        // Receive response for B (correlationKey = "200") on Association A
        // We simulate finding by probeId but with wrong correlation key by attempting to pop with "200" from A
        val poppedFromA = sessionA.popMatchingProbe("200")
        assertNull("Should not find probe with correlationKey 200 in session A", poppedFromA)

        // And from B, we try to pop with "100"
        val poppedFromB = sessionB.popMatchingProbe("100")
        assertNull("Should not find probe with correlationKey 100 in session B", poppedFromB)
        
        // Correct pop
        val correctPopB = sessionB.popMatchingProbe("200")
        assertNotNull("Should find probe with correlationKey 200 in session B", correctPopB)
        
        if (correctPopB != null) {
            DpiStrategySelector.recordResult(
                strategy = correctPopB.strategy,
                success = true,
                transport = TransportType.UDP
            )
        }

        assertEquals(0, stateA.successCount.get())
        assertEquals(1, stateB.successCount.get())
    }
}

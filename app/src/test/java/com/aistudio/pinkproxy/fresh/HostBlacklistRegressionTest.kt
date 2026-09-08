package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class HostBlacklistRegressionTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState("DEFAULT")
    }

    @Test
    fun `test successful strategy does not clear blacklist of other strategies`() = runTest {
        val host = "test-domain.com"
        val transport = TransportType.TCP
        val profileId = "DEFAULT"
        
        // 1. Blacklist two strategies for the host
        val badStrategy1 = BypassStrategy.SNI_SPLIT
        val badStrategy2 = BypassStrategy.ZAPRET_EXTREME
        val expiryTime = System.currentTimeMillis() + 600_000L
        
        StrategyStateRepository.hostStrategyBlacklist[HostStrategyBlacklistKey(host, transport, profileId, badStrategy1)] = expiryTime
        StrategyStateRepository.hostStrategyBlacklist[HostStrategyBlacklistKey(host, transport, profileId, badStrategy2)] = expiryTime
        
        // Ensure they are in the blacklist
        assertNotNull(StrategyStateRepository.hostStrategyBlacklist[HostStrategyBlacklistKey(host, transport, profileId, badStrategy1)])
        
        // 2. Report success for a DIFFERENT strategy
        val goodStrategy = BypassStrategy.DNS_OVER_TCP
        DpiStrategySelector.recordResult(
            strategy = goodStrategy,
            success = true,
            transport = transport,
            host = host,
            quality = ObservationQuality.VALID_PROTOCOL_RESPONSE,
            category = HostCategory.OTHER
        )
        
        // 3. Verify the good strategy is not blacklisted (it shouldn't be anyway, but it definitely shouldn't be added)
        assertNull(StrategyStateRepository.hostStrategyBlacklist[HostStrategyBlacklistKey(host, transport, profileId, goodStrategy)])
        
        // 4. Verify the bad strategies are STILL in the blacklist
        assertNotNull("SNI_SPLIT should still be blacklisted", StrategyStateRepository.hostStrategyBlacklist[HostStrategyBlacklistKey(host, transport, profileId, badStrategy1)])
        assertNotNull("ZAPRET_EXTREME should still be blacklisted", StrategyStateRepository.hostStrategyBlacklist[HostStrategyBlacklistKey(host, transport, profileId, badStrategy2)])
    }
}

package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class EscalationGraphCycleTest {

    @Before
    fun setup() {
        StrategyStateRepository.clearProfileState(NetworkProfile.UNKNOWN.id)
    }

    @Test
    fun `test fallback escalation graph context mapping`() = runTest {
        val context = CandidateEngine.SelectionContext(
            profileId = NetworkProfile.UNKNOWN.id,
            host = "blocked.example.com",
            transport = TransportType.TCP,
            category = HostCategory.OTHER
        )
        
        val fallback = DpiStrategySelector.getFallbackStrategy(
            strategy = BypassStrategy.SNI_SPLIT,
            transport = TransportType.TCP,
            context = context
        )
        
        assertNotNull("Fallback must return a valid strategy", fallback)
    }
}

package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class ProfileLearningRegressionTest {

    @Before
    fun setup() {
        StrategyStateRepository.networkStrategyMemory.clear()
        StrategyStateRepository.contextualHostMemory.clear()
        StrategyStateRepository.hostStrategyBlacklist.clear()
        StrategyStateRepository.getAllContextStates().forEach { (k, _) ->
            StrategyStateRepository.clearProfileState(k.profileId)
        }
    }

    @Test
    fun `test profile learning is preserved across network switches`() = runTest {
        val context = RuntimeEnvironment.getApplication()
        val dpiEngine = DpiEngine
        
        val profileA = NetworkProfile("PROFILE_A", NetworkType.WIFI, "Wi-Fi")
        val profileB = NetworkProfile("PROFILE_B", NetworkType.MOBILE, "Cellular")
        
        val setCurrentProfile = NetworkProfileManager::class.java.getDeclaredMethod("setCurrentProfile", NetworkProfile::class.java)
        setCurrentProfile.isAccessible = true
        
        // 1. Learn A
        setCurrentProfile.invoke(NetworkProfileManager, profileA)
        dpiEngine.markSuccess(
            BypassStrategy.SNI_SPLIT,
            TransportType.TCP,
            "test-a.com",
            100L,
            ObservationQuality.APPLICATION_DATA_EXCHANGED
        )
        
        // Assert A learned
        var stateA = StrategyStateRepository.getStrategyState(BypassStrategy.SNI_SPLIT, TransportType.TCP, HostCategory.OTHER, "PROFILE_A")
        assertEquals(1, stateA.successCount.get())
        
        // 2. Switch B
        dpiEngine.switchNetworkProfile(profileA, profileB, context)
        setCurrentProfile.invoke(NetworkProfileManager, profileB)
        
        // 3. Learn B
        dpiEngine.markSuccess(
            BypassStrategy.ZAPRET_EXTREME,
            TransportType.TCP,
            "test-b.com",
            120L,
            ObservationQuality.APPLICATION_DATA_EXCHANGED
        )
        
        // Assert B learned
        var stateB = StrategyStateRepository.getStrategyState(BypassStrategy.ZAPRET_EXTREME, TransportType.TCP, HostCategory.OTHER, "PROFILE_B")
        assertEquals(1, stateB.successCount.get())
        
        // 4. Switch back to A
        dpiEngine.switchNetworkProfile(profileB, profileA, context)
        setCurrentProfile.invoke(NetworkProfileManager, profileA)
        
        // 5. Assert A learning preserved
        stateA = StrategyStateRepository.getStrategyState(BypassStrategy.SNI_SPLIT, TransportType.TCP, HostCategory.OTHER, "PROFILE_A")
        assertEquals("Profile A learning should be preserved", 1, stateA.successCount.get())
        
        stateB = StrategyStateRepository.getStrategyState(BypassStrategy.ZAPRET_EXTREME, TransportType.TCP, HostCategory.OTHER, "PROFILE_B")
        assertEquals("Profile B learning should be preserved", 1, stateB.successCount.get())
    }
}

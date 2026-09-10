package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class InitialStatePolicyTest {

    @Before
    fun setup() {
        BypassConfig.isStrictBypassMode = false
        BypassConfig.isAutoTuning = true
        BypassConfig.autoTuningMode = AutoTuningMode.STABLE
        StrategyStateRepository.clearProfileState("DEFAULT")
    }

    @Test
    fun `test bypass config fallback logic ensures policy gate`() = runTest {
        val context = CandidateEngine.SelectionContext(TransportType.TCP)
        // We set global strategy to something EXTREME but the profile is STABLE
        // We simulate this by directly asking the gate to resolve an EXTREME strategy
        // It must fallback to a LIGHT/MEDIUM/DIRECT strategy
        
        val requestedExtreme = BypassStrategy.ZAPRET_EXTREME
        val result = StrategyPolicyGate.resolveOrFallback(requestedExtreme, context)
        
        assertTrue("STABLE mode must not allow EXTREME strategy at initialization", result.group != StrategyGroup.EXTREME)
    }

    @Test
    fun `test bypass config initializes with DIRECT if saved strategy is incompatible`() {
        val app = RuntimeEnvironment.getApplication()
        val prefs = app.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
        prefs.edit().putString("global_strategy", BypassStrategy.ZAPRET_EXTREME.name).apply()
        
        BypassConfig.autoTuningMode = AutoTuningMode.STABLE
        
        BypassConfig.loadTuningSettings(app)
        
        val loaded = BypassConfig.tcpStrategy.value
        assertTrue("Loaded strategy must not be extreme in STABLE mode", loaded?.group != StrategyGroup.EXTREME)
    }
}

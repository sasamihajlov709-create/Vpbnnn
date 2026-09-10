package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class StrategyCompatibilityTest {

    @Test
    fun `test strategy compatibility flags`() {
        // TCP_OOB_DESYNC requires packet engine
        assertTrue(BypassStrategy.TCP_OOB_DESYNC.compatibility.requiresPacketEngine)
        
        // SNI_SPLIT preservesProtocolSemantics is false because it fragments the stream at TLS level
        assertFalse(BypassStrategy.SNI_SPLIT.compatibility.preservesProtocolSemantics)
        
        // TLS_PAD does not require packet engine and preserves semantics mostly
        assertFalse(BypassStrategy.TLS_PAD.compatibility.requiresPacketEngine)
    }
}

package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PinkProxyServerTest {

    @Test
    fun testBypassConfigDefaults() {
        // Just verify BypassConfig is accessible and defaults are set
        assertTrue(BypassConfig.isAutoTuning)
        assertTrue(BypassConfig.blockQuic)
    }

}

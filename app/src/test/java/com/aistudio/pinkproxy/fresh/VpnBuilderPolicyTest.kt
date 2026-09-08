package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class VpnBuilderPolicyTest {

    @Test
    fun `test allowBypass is false by default in BypassConfig`() {
        val allowBypass = BypassConfig.allowBypass.value
        assertFalse("allowBypass must be strictly disabled by default to prevent traffic leaks", allowBypass)
    }
}

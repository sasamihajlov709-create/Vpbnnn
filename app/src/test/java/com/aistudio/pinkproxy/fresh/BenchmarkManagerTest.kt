package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BenchmarkManagerTest {

    @Test
    fun testInitialBenchmarkState() {
        assertFalse(BenchmarkManager.isRunning.value)
        assertEquals(0f, BenchmarkManager.progress.value, 0.001f)
        assertTrue(BenchmarkManager.results.value.isEmpty())
    }

    @Test
    fun testBenchmarkResultDataClass() {
        val result = BenchmarkManager.BenchmarkResult(
            strategy = BypassStrategy.SNI_SPLIT,
            isTested = true,
            isSuccess = true,
            latencyMs = 65L,
            error = null
        )

        assertEquals(BypassStrategy.SNI_SPLIT, result.strategy)
        assertTrue(result.isTested)
        assertTrue(result.isSuccess)
        assertEquals(65L, result.latencyMs)
        assertNull(result.error)
    }
}

package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlinx.coroutines.*
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class VpnShutdownCoordinatorTest {

    @Test
    fun testShutdownExecutesRegisteredTasks() = runBlocking {
        val task1Executed = AtomicBoolean(false)
        val task2Executed = AtomicBoolean(false)

        VpnShutdownCoordinator.registerCleanup {
            task1Executed.set(true)
        }
        VpnShutdownCoordinator.registerCleanup {
            task2Executed.set(true)
        }

        val completed = AtomicBoolean(false)
        val job = VpnShutdownCoordinator.shutdownAsync(
            context = null,
            timeoutMs = 1000L,
            onComplete = {
                completed.set(true)
            }
        )

        job.join()

        assertTrue("Task 1 must be executed", task1Executed.get())
        assertTrue("Task 2 must be executed", task2Executed.get())
        assertTrue("Shutdown completion callback must fire", completed.get())
    }

    @Test
    fun testSafeCloseHandlesExceptionsGracefully() {
        val brokenCloseable = Closeable {
            throw java.io.IOException("Socket already closed")
        }

        // Must not throw or crash
        VpnShutdownCoordinator.safeClose(brokenCloseable)
        VpnShutdownCoordinator.safeClose(null)
    }
}

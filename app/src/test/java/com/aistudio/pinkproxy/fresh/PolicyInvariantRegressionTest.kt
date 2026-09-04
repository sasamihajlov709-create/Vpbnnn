package com.aistudio.pinkproxy.fresh

import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Socket
import java.net.InetAddress
import java.io.ByteArrayOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class PolicyInvariantRegressionTest {

    @Before
    fun setup() {
        BypassConfig.isStrictBypassMode = false
    }

    @After
    fun tearDown() {
        BypassConfig.isStrictBypassMode = false
    }

    @Test
    fun testBypassApplierEnforcesPolicyGateTcp() {
        BypassConfig.isStrictBypassMode = true
        val config = SessionConfig(
            strategy = BypassStrategy.DIRECT,
            frag1 = 0,
            delay1 = 0,
            fakeTtl = 0
        )
        
        // Use a dummy socket/stream. The applier should throw before using them.
        try {
            // We use coroutine runBlocking pattern but we can just use normal try-catch here as it's not a suspend function in this specific check.
            kotlinx.coroutines.runBlocking {
                BypassApplier.applyBypass(
                    Socket(), 
                    ByteArrayOutputStream(), 
                    ByteArray(10), 
                    10, 
                    config, 
                    "test.com"
                )
            }
            fail("Expected PolicyViolationException")
        } catch (e: PolicyViolationException) {
            // Success
        }
    }

    @Test
    fun testBypassApplierEnforcesPolicyGateUdp() {
        BypassConfig.isStrictBypassMode = true
        val config = SessionConfig(
            strategy = BypassStrategy.DIRECT,
            frag1 = 0,
            delay1 = 0,
            fakeTtl = 0
        )
        
        try {
            kotlinx.coroutines.runBlocking {
                val packet = DatagramPacket(ByteArray(10), 10, InetAddress.getByName("127.0.0.1"), 80)
                BypassApplier.applyUdpBypass(
                    DatagramSocket(), 
                    packet, 
                    config, 
                    "test.com"
                )
            }
            fail("Expected PolicyViolationException")
        } catch (e: PolicyViolationException) {
            // Success
        }
    }
}

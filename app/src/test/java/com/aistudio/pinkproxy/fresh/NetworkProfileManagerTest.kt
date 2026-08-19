package com.aistudio.pinkproxy.fresh

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class NetworkProfileManagerTest {

    @Before
    fun setUp() {
        NetworkProfileManager.setProfileForTesting(NetworkProfile.UNKNOWN)
    }

    @Test
    fun testInitialProfile() {
        assertEquals(NetworkProfile.UNKNOWN, NetworkProfileManager.currentProfile.value)
    }

    @Test
    fun testProfileSwitchAndListenerNotification() {
        var oldReceived: NetworkProfile? = null
        var newReceived: NetworkProfile? = null

        val listener: (NetworkProfile, NetworkProfile) -> Unit = { oldP, newP ->
            oldReceived = oldP
            newReceived = newP
        }

        NetworkProfileManager.addListener(listener)

        val wifiProfile = NetworkProfile(
            id = "wifi_test_123",
            type = NetworkType.WIFI,
            displayName = "Wi-Fi (192.168.1.1)",
            carrierOrGateway = "192.168.1.1"
        )

        NetworkProfileManager.setProfileForTesting(wifiProfile)
        assertEquals(wifiProfile, NetworkProfileManager.currentProfile.value)
        assertEquals(NetworkProfile.UNKNOWN, oldReceived)
        assertEquals(wifiProfile, newReceived)

        NetworkProfileManager.removeListener(listener)
    }
}

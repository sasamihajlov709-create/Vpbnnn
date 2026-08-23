package com.aistudio.pinkproxy.fresh

import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.aistudio.pinkproxy.fresh.ui.ActiveFlowsContent
import com.aistudio.pinkproxy.fresh.ui.CensorshipFingerprintCard
import com.aistudio.pinkproxy.fresh.ui.LogsContent
import com.aistudio.pinkproxy.fresh.ui.PowerButton
import com.aistudio.pinkproxy.fresh.ui.StatusBadge
import com.aistudio.pinkproxy.fresh.ui.theme.MyApplicationTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config

@RunWith(AndroidJUnit4::class)
@Config(sdk = [34])
class UiRenderAndMetricsStressTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun testStatusBadgeAndPowerButtonRendering() {
        composeTestRule.setContent {
            MyApplicationTheme {
                val transition = rememberInfiniteTransition(label = "test")
                Box(modifier = Modifier.fillMaxSize()) {
                    StatusBadge(isHealthy = true, isInternet = true, isProbing = false)
                    PowerButton(state = VpnLifecycleState.RUNNING, onToggle = {}, transition = transition)
                }
            }
        }
        composeTestRule.waitForIdle()
    }

    @Test
    fun testActiveFlowsAndSpeedGraphStressRendering() {
        val testFlows = listOf(
            ActiveFlow(
                id = "flow_1",
                host = "rr1---sn-4g5ednle.googlevideo.com",
                type = "TCP",
                strategy = BypassStrategy.TCP_COMBINED_HYBRID,
                reasoning = "Optimized for Google Video CDN",
                bytesSent = 154200L,
                bytesReceived = 15840290L
            ),
            ActiveFlow(
                id = "flow_2",
                host = "gateway.discord.gg",
                type = "UDP",
                strategy = BypassStrategy.UDP_DISCORD_FAKE,
                reasoning = "High resilience on STUN/Voice gateway",
                bytesSent = 4096L,
                bytesReceived = 8192L
            )
        )

        composeTestRule.setContent {
            MyApplicationTheme {
                Box(modifier = Modifier.fillMaxSize()) {
                    ActiveFlowsContent(flows = testFlows)
                    CensorshipFingerprintCard(
                        fingerprint = DpiAnalyzer.CensorshipFingerprint(
                            rstRate = 0.15,
                            sniBlockRate = 0.05,
                            udpBlockRate = 0.01,
                            timeoutRate = 0.01,
                            stallRate = 0.02,
                            dnsBlockRate = 0.0,
                            jitter = 24.5,
                            intensity = 35
                        )
                    )
                }
            }
        }
        composeTestRule.waitForIdle()
    }

    @Test
    fun testLogsContentCopyAndRendering() {
        val sampleRecoveryLogs = listOf(
            "Auto-healing triggered: switched to TCP_COMBINED_HYBRID",
            "Resolved DoH latency: 32ms via Cloudflare Primary"
        )
        val sampleTrafficLogs = listOf(
            "Direct TCP connection opened to 142.250.180.14:443",
            "QUIC filtered: fallback to HTTP/2 successful"
        )

        composeTestRule.setContent {
            MyApplicationTheme {
                Box(modifier = Modifier.fillMaxSize()) {
                    LogsContent(recovery = sampleRecoveryLogs, traffic = sampleTrafficLogs)
                }
            }
        }
        composeTestRule.waitForIdle()
    }
}

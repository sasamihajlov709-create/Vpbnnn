package com.aistudio.pinkproxy.fresh

import android.content.Context
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.util.concurrent.CancellationException

class VpnStartupCoordinator(
    private val vpnService: PinkVpnService,
    private val vpnTunnelManager: VpnTunnelManager,
    private val transportEngineCoordinator: TransportEngineCoordinator,
    private val recoveryCoordinator: VpnRecoveryCoordinator,
    private val healthMonitor: VpnHealthMonitor
) {

    suspend fun startVpn(
        proxyPort: Int,
        proxySecret: String,
        session: VpnSession,
        isExcludeMode: Boolean,
        selectedPackages: Set<String>,
        onProxyServerStarted: (PinkProxyServer) -> Unit
    ): Boolean = withContext(ProxyDispatcher.io) {
        try {
            Log.i("VpnStartupCoordinator", "Starting VPN internal sequence...")
            
            ProxyStats.reset(false)
            ServiceChecker.proxyPort = proxyPort

            // 1. Initialize DNS
            VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Initializing DNS resolver...")
            RobustResolver.initialize(session.dnsScope)
            RobustResolver.startDnsOptimizer(session.dnsScope, vpnService)

            // 2. Start Proxy Server
            VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Starting SOCKS5/HTTP core proxy...")
            val newProxy = PinkProxyServer(vpnService, proxyPort, proxySecret)
            newProxy.start(session.dataPlaneScope.coroutineContext[Job])
            onProxyServerStarted(newProxy)

            // 3. Start DPI Engine & Censorship Expert
            DpiEngine.start(vpnService)
            CensorshipExpert.start()

            val systemDnsIps = try {
                val cm = vpnService.getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
                val activeNet = cm.activeNetwork
                val linkProps = cm.getLinkProperties(activeNet)
                linkProps?.dnsServers?.mapNotNull { it.hostAddress }?.filter { it.contains(".") } ?: emptyList()
            } catch (e: Exception) {
                emptyList()
            }

            val dnsServers = when (BypassConfig.dnsType) {
                DnsType.SYSTEM -> if (systemDnsIps.isNotEmpty()) systemDnsIps else listOf("1.1.1.1", "8.8.8.8")
                DnsType.GOOGLE_DOH -> listOf("8.8.8.8", "8.8.4.4")
                DnsType.CLOUDFLARE_DOH -> listOf("1.1.1.1", "1.0.0.1")
                DnsType.ADGUARD_DOH -> listOf("94.140.14.14", "94.140.15.15")
                DnsType.QUAD9_DOH -> listOf("9.9.9.9", "149.112.112.112")
                DnsType.CUSTOM_UDP, DnsType.CUSTOM_TCP, DnsType.CUSTOM_DOH -> {
                    val ips = extractIpsFromDnsUrl(BypassConfig.customDnsUrl)
                    if (ips.isNotEmpty()) ips else listOf("1.1.1.1", "8.8.8.8")
                }
                else -> if (systemDnsIps.isNotEmpty()) systemDnsIps else listOf("1.1.1.1", "8.8.8.8")
            }

            // 4. Establish TUN interface
            VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Configuring TUN interface...")
            var isTunFallback = false
            val pfd = try {
                vpnTunnelManager.establish(
                    sessionName = "PinkProxy VPN",
                    mtu = BypassConfig.getMtuForTransport(TransportType.TCP),
                    addressV4 = "10.0.0.2",
                    prefixV4 = 24,
                    dnsServers = dnsServers,
                    includeIpv6 = BypassConfig.includeIpv6,
                    isExcludeMode = isExcludeMode,
                    selectedPackages = selectedPackages,
                    appPackageName = vpnService.packageName,
                    allowBypass = BypassConfig.allowBypass.value,
                    isBlocking = true
                ) ?: throw java.io.IOException("Failed to establish tunnel interface")
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Log.w("VpnStartupCoordinator", "Emergency fallback TUN activated! Reason: ${e.message}")
                isTunFallback = true
                VpnRuntimeState.updateState(VpnLifecycleState.TUN_FALLBACK, "Fallback tunnel mode activated (IPv4-only)")
                vpnTunnelManager.establish(
                    sessionName = "PinkProxy VPN",
                    mtu = 1400,
                    addressV4 = "10.0.0.2",
                    prefixV4 = 24,
                    dnsServers = listOf("8.8.8.8"),
                    includeIpv6 = false,
                    isExcludeMode = isExcludeMode,
                    selectedPackages = selectedPackages,
                    appPackageName = vpnService.packageName,
                    allowBypass = BypassConfig.allowBypass.value,
                    isBlocking = true
                ) ?: throw e
            }

            AutoTtlProber.startProbing(session.learningScope, vpnService)

            // 5. Start tun2socks engine
            VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Binding transport engine to TUN...")
            transportEngineCoordinator.start(pfd, proxyPort, proxySecret, session.controlPlaneScope) { e ->
                VpnRuntimeState.updateState(VpnLifecycleState.ERROR, "Transport engine error: ${e.localizedMessage}")
                recoveryCoordinator.triggerRestart()
            }

            // 6. Execute Multi-Tier Transport & Data-Plane Health Probes before marking RUNNING
            VpnRuntimeState.updateState(VpnLifecycleState.PROBING, "Verifying local proxy transport & data-plane...")
            val localProbeSuccess = performLocalSocksHealthProbe(proxyPort, proxySecret)
            if (!localProbeSuccess) {
                Log.w("VpnStartupCoordinator", "Local proxy health probe failed! Triggering restart recovery")
                VpnRuntimeState.updateState(VpnLifecycleState.DEGRADED, "Local proxy probe failed, attempting recovery...")
                vpnService.restartProxyServer()
                val retrySuccess = performLocalSocksHealthProbe(proxyPort, proxySecret)
                if (!retrySuccess) {
                    throw java.io.IOException("Critical: Core proxy failed health verification on port $proxyPort")
                }
            }

// Perform Multi-Layer Data-Plane readiness check through proxy
            val diagnostic = DiagnosticManager.runFullDiagnostic()

            // 7. Now that proxy & tun2socks are fully running, start health checkers & monitors
            RuntimeCoordinator.initialize(vpnService)
            RecoveryStateMachine.start(session.recoveryScope)
            ServiceChecker.startChecking(session.controlPlaneScope, vpnService)
            healthMonitor.start(session.controlPlaneScope)

if (diagnostic.level < DiagnosticManager.HealthLevel.L4_TCP_REACHABLE) {
                Log.w("VpnStartupCoordinator", "Data-plane probe failed (Level ${diagnostic.level}), setting state to DEGRADED.")
                VpnRuntimeState.updateState(VpnLifecycleState.DEGRADED, diagnostic.recommendation)
            } else {
                Log.i("VpnStartupCoordinator", "Data-plane probe passed (Level ${diagnostic.level})!")
                VpnRuntimeState.updateState(if (isTunFallback) VpnLifecycleState.TUN_FALLBACK else VpnLifecycleState.RUNNING)
                VpnRuntimeState.clearError()
            }
            
            return@withContext true

        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.e("VpnStartupCoordinator", "Error starting VPN", e)
            VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Critical startup error: ${e.localizedMessage}")
            return@withContext false
        }
    }


    private fun extractIpsFromDnsUrl(url: String): List<String> {
        val ipRegex = Regex("([0-9]{1,3}\\.){3}[0-9]{1,3}|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])")
        return ipRegex.findAll(url).map { it.value }.toList()
    }

    private suspend fun performLocalSocksHealthProbe(proxyPort: Int, secret: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val sock = java.net.Socket()
            sock.connect(java.net.InetSocketAddress("127.0.0.1", proxyPort), 1500)
            val out = sock.getOutputStream()
            val input = sock.getInputStream()

            // Request auth (Method 02 = Username/Password)
            out.write(byteArrayOf(0x05, 0x01, 0x02))
            out.flush()

            val ack = ByteArray(2)
            var read = input.read(ack)
            if (read < 2 || ack[0] != 0x05.toByte() || ack[1] != 0x02.toByte()) {
                sock.close()
                return@withContext false
            }

            val uBytes = secret.toByteArray()
            val authReq = ByteArray(1 + 1 + uBytes.size + 1 + uBytes.size)
            authReq[0] = 0x01
            authReq[1] = uBytes.size.toByte()
            System.arraycopy(uBytes, 0, authReq, 2, uBytes.size)
            authReq[2 + uBytes.size] = uBytes.size.toByte()
            System.arraycopy(uBytes, 0, authReq, 3 + uBytes.size, uBytes.size)

            out.write(authReq)
            out.flush()

            val authAck = ByteArray(2)
            read = input.read(authAck)
            sock.close()

            if (read >= 2 && authAck[1] == 0x00.toByte()) {
                true
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
}

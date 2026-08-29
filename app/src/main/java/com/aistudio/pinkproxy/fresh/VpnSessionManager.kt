package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

/**
 * Encapsulates the entire state of a single VPN connection lifecycle.
 * When the VPN is stopped, this session is cancelled, guaranteeing that
 * no zombie coroutines from a previous session survive to interfere
 * with a subsequent connection.
 */
class VpnSession(val vpnService: VpnService) {
    private val sessionJob = SupervisorJob()
    
    // Dedicated scopes tied strictly to this session's lifecycle
    val dataPlaneScope = CoroutineScope(ProxyDispatcher.io + sessionJob + ProxyDispatcher.globalHandler)
    val controlPlaneScope = CoroutineScope(ProxyDispatcher.scheduler + sessionJob + ProxyDispatcher.globalHandler)
    val dnsScope = CoroutineScope(ProxyDispatcher.dnsResolver + sessionJob + ProxyDispatcher.globalHandler)
    val learningScope = CoroutineScope(ProxyDispatcher.io + sessionJob + ProxyDispatcher.globalHandler)
    val recoveryScope = CoroutineScope(ProxyDispatcher.scheduler + sessionJob + ProxyDispatcher.globalHandler)

    fun cancel() {
        sessionJob.cancel()
    }
}

object VpnSessionManager {
    @Volatile
    var currentSession: VpnSession? = null
        private set

    fun startSession(vpnService: VpnService): VpnSession {
        currentSession?.cancel()
        val newSession = VpnSession(vpnService)
        currentSession = newSession
        return newSession
    }

    fun stopSession() {
        currentSession?.cancel()
        currentSession = null
    }
}

package com.aistudio.pinkproxy.fresh

import java.net.InetAddress
import java.net.DatagramSocket
import kotlinx.coroutines.Job
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

data class UdpSessionKey(
    val clientAddress: InetAddress,
    val clientPort: Int,
    val destinationHost: String,
    val destinationPort: Int
)

data class UdpPendingProbe(
    val host: String,
    val strategy: BypassStrategy,
    val sentTime: Long = System.currentTimeMillis(),
    val probeId: String = java.util.UUID.randomUUID().toString(),
    val correlationKey: String? = null
)

class UdpAssociation(
    val key: UdpSessionKey,
    val socksSessionId: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    @Volatile var lastActivity: Long = System.currentTimeMillis(),
    @Volatile var packetsSent: Long = 0L,
    @Volatile var packetsReceived: Long = 0L,
    @Volatile var bytesSent: Long = 0L,
    @Volatile var bytesReceived: Long = 0L,
    @Volatile var strategy: BypassStrategy
) {
    var outSocket: DatagramSocket? = null
    var targetInet: InetAddress? = null
    var readerJob: Job? = null
    
    private val pendingProbes = ConcurrentLinkedQueue<UdpPendingProbe>()
    private val correlatedProbes = ConcurrentHashMap<String, UdpPendingProbe>()
    
    fun addProbe(probe: UdpPendingProbe) {
        if (probe.correlationKey != null) {
            correlatedProbes[probe.correlationKey] = probe
        }
        pendingProbes.offer(probe)
        cleanExpiredProbes()
    }

    fun popMatchingProbe(correlationKey: String? = null): UdpPendingProbe? {
        cleanExpiredProbes()
        if (correlationKey != null) {
            val probe = correlatedProbes.remove(correlationKey)
            if (probe != null) {
                pendingProbes.remove(probe)
                return probe
            }
        }
        val probe = pendingProbes.poll()
        if (probe?.correlationKey != null) {
            correlatedProbes.remove(probe.correlationKey)
        }
        return probe
    }
    
    fun popProbe(): UdpPendingProbe? {
        return popMatchingProbe(null)
    }

    fun removeProbe(probe: UdpPendingProbe?) {
        if (probe == null) return
        pendingProbes.remove(probe)
        if (probe.correlationKey != null) {
            correlatedProbes.remove(probe.correlationKey)
        }
    }

    private fun cleanExpiredProbes(maxAgeMs: Long = 10_000L) {
        val now = System.currentTimeMillis()
        val it = pendingProbes.iterator()
        while (it.hasNext()) {
            val p = it.next()
            if (now - p.sentTime > maxAgeMs) {
                it.remove()
                if (p.correlationKey != null) {
                    correlatedProbes.remove(p.correlationKey)
                }
            }
        }
    }

    fun close() {
        readerJob?.cancel()
        readerJob = null
        try {
            outSocket?.close()
        } catch (e: Exception) {}
        outSocket = null
        pendingProbes.clear()
        correlatedProbes.clear()
    }
}

object UdpAssociationTable {
    private val sessions = ConcurrentHashMap<UdpSessionKey, UdpAssociation>()

    fun getOrCreateSession(
        sessionId: String,
        clientAddress: InetAddress,
        clientPort: Int,
        destinationHost: String,
        destinationPort: Int,
        strategy: BypassStrategy
    ): UdpAssociation {
        val key = UdpSessionKey(clientAddress, clientPort, destinationHost, destinationPort)
        return sessions.computeIfAbsent(key) {
            UdpAssociation(key = it, socksSessionId = sessionId, strategy = strategy)
        }.also {
            it.lastActivity = System.currentTimeMillis()
        }
    }

    fun getSession(key: UdpSessionKey): UdpAssociation? = sessions[key]

    fun removeSession(key: UdpSessionKey) {
        sessions.remove(key)?.close()
    }

    fun removeSessionsForSocksSession(sessionId: String): Int {
        var removedCount = 0
        val iterator = sessions.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value.socksSessionId == sessionId) {
                entry.value.close()
                iterator.remove()
                removedCount++
            }
        }
        return removedCount
    }

    fun touchSession(key: UdpSessionKey, sentBytes: Long = 0L, receivedBytes: Long = 0L) {
        val entry = sessions[key] ?: return
        entry.lastActivity = System.currentTimeMillis()
        if (sentBytes > 0) {
            entry.packetsSent++
            entry.bytesSent += sentBytes
        }
        if (receivedBytes > 0) {
            entry.packetsReceived++
            entry.bytesReceived += receivedBytes
        }
    }

    fun cleanupExpiredSessions(maxIdleDurationMs: Long = 90_000L): Int {
        val now = System.currentTimeMillis()
        var removedCount = 0
        val iterator = sessions.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.lastActivity > maxIdleDurationMs) {
                entry.value.close()
                iterator.remove()
                removedCount++
            }
        }
        return removedCount
    }

    fun clear() {
        sessions.values.forEach {
            it.close()
        }
        sessions.clear()
    }
    
    fun getAllSessions(): Collection<UdpAssociation> = sessions.values
    
    val activeCount: Int get() = sessions.size
}

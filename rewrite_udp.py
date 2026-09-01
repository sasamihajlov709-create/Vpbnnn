import re

# Rewrite UdpAssociationTable.kt
with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpAssociationTable.kt", "w") as f:
    f.write("""package com.aistudio.pinkproxy.fresh

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
    val sentTime: Long
)

class UdpAssociation(
    val key: UdpSessionKey,
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
    
    fun addProbe(probe: UdpPendingProbe) {
        pendingProbes.offer(probe)
    }
    
    fun popProbe(): UdpPendingProbe? {
        return pendingProbes.poll()
    }
}

object UdpAssociationTable {
    private val sessions = ConcurrentHashMap<UdpSessionKey, UdpAssociation>()

    fun getOrCreateSession(
        clientAddress: InetAddress,
        clientPort: Int,
        destinationHost: String,
        destinationPort: Int,
        strategy: BypassStrategy
    ): UdpAssociation {
        val key = UdpSessionKey(clientAddress, clientPort, destinationHost, destinationPort)
        return sessions.computeIfAbsent(key) {
            UdpAssociation(key = it, strategy = strategy)
        }.also {
            it.lastActivity = System.currentTimeMillis()
        }
    }

    fun getSession(key: UdpSessionKey): UdpAssociation? = sessions[key]

    fun removeSession(key: UdpSessionKey) {
        sessions.remove(key)?.let {
            it.readerJob?.cancel()
            try { it.outSocket?.close() } catch (e: Exception) {}
        }
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
                entry.value.readerJob?.cancel()
                try { entry.value.outSocket?.close() } catch (e: Exception) {}
                iterator.remove()
                removedCount++
            }
        }
        return removedCount
    }

    fun clear() {
        sessions.values.forEach {
            it.readerJob?.cancel()
            try { it.outSocket?.close() } catch (e: Exception) {}
        }
        sessions.clear()
    }
    
    fun getAllSessions(): Collection<UdpAssociation> = sessions.values
    
    val activeCount: Int get() = sessions.size
}
""")


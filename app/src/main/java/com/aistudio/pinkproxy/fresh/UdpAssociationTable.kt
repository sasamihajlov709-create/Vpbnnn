package com.aistudio.pinkproxy.fresh

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * 4-Tuple key uniquely identifying a client UDP socket association:
 * (Client IP, Client Port, Destination IP/Host, Destination Port)
 */
data class UdpSessionKey(
    val clientAddress: InetAddress,
    val clientPort: Int,
    val destinationHost: String,
    val destinationPort: Int
)

/**
 * Represents metadata and state for an active UDP association flow.
 */
data class UdpSessionEntry(
    val key: UdpSessionKey,
    val createdAt: Long = System.currentTimeMillis(),
    @Volatile var lastActivity: Long = System.currentTimeMillis(),
    @Volatile var packetsSent: Long = 0L,
    @Volatile var packetsReceived: Long = 0L,
    @Volatile var bytesSent: Long = 0L,
    @Volatile var bytesReceived: Long = 0L,
    val strategy: BypassStrategy
)

/**
 * Thread-safe Table managing multiple client UDP associations.
 * Prevents single-client state collisions and provides LRU/TTL aging.
 */
object UdpAssociationTable {
    private val sessions = ConcurrentHashMap<UdpSessionKey, UdpSessionEntry>()

    fun getOrCreateSession(
        clientAddress: InetAddress,
        clientPort: Int,
        destinationHost: String,
        destinationPort: Int,
        strategy: BypassStrategy
    ): UdpSessionEntry {
        val key = UdpSessionKey(clientAddress, clientPort, destinationHost, destinationPort)
        return sessions.computeIfAbsent(key) {
            UdpSessionEntry(key = it, strategy = strategy)
        }.also {
            it.lastActivity = System.currentTimeMillis()
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
                iterator.remove()
                removedCount++
            }
        }
        return removedCount
    }

    fun clear() {
        sessions.clear()
    }

    val activeCount: Int get() = sessions.size
}

package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.flow.*
import java.util.concurrent.atomic.AtomicLong

object TrafficMonitor {
    private val rawBytesTransferred = AtomicLong(0)
    
    private val _bytesTransferred = MutableStateFlow(0L)
    val bytesTransferred: StateFlow<Long> = _bytesTransferred.asStateFlow()

    private val _speedBytesPerSecond = MutableStateFlow(0L)
    val speedBytesPerSecond: StateFlow<Long> = _speedBytesPerSecond.asStateFlow()

    private val _speedHistory = MutableStateFlow(emptyList<Long>())
    val speedHistory: StateFlow<List<Long>> = _speedHistory.asStateFlow()

    private val _topHosts = MutableStateFlow(emptyList<Pair<String, Int>>())
    val topHosts: StateFlow<List<Pair<String, Int>>> = _topHosts.asStateFlow()

    private val _activeConnections = MutableStateFlow(0)
    val activeConnections: StateFlow<Int> = _activeConnections.asStateFlow()

    fun updateBytes(delta: Long) {
        rawBytesTransferred.addAndGet(delta)
    }

    fun updateConnections(delta: Int) {
        _activeConnections.update { (it + delta).coerceAtLeast(0) }
    }

    fun addTraffic(host: String) {
        _topHosts.update { current ->
            val hosts = current.toMutableList()
            val idx = hosts.indexOfFirst { it.first == host }
            if (idx != -1) hosts[idx] = host to hosts[idx].second + 1 else hosts.add(host to 1)
            hosts.sortedByDescending { it.second }.take(10)
        }
    }

    fun updateSpeedMetrics() {
        val currentBytes = rawBytesTransferred.get()
        val oldBytes = _bytesTransferred.value
        _bytesTransferred.value = currentBytes
        
        val speed = (currentBytes - oldBytes).coerceAtLeast(0)
        _speedBytesPerSecond.value = speed

        _speedHistory.update { current ->
            val newList = ArrayList<Long>(60)
            newList.add(speed)
            if (current.size > 59) newList.addAll(current.subList(0, 59)) else newList.addAll(current)
            newList
        }
    }

    fun reset() {
        rawBytesTransferred.set(0)
        _bytesTransferred.value = 0
        _speedBytesPerSecond.value = 0
        _speedHistory.value = emptyList()
        _topHosts.value = emptyList()
        _activeConnections.value = 0
    }

    fun getRawBytes(): Long = rawBytesTransferred.get()
}

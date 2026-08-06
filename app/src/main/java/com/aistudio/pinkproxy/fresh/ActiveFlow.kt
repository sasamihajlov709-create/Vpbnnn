package com.aistudio.pinkproxy.fresh

data class ActiveFlow(
    val id: String,
    val host: String,
    val type: String, // "TCP" or "UDP"
    val strategy: BypassStrategy,
    val startTime: Long = System.currentTimeMillis(),
    var bytesSent: Long = 0,
    var bytesReceived: Long = 0,
    var status: String = "ACTIVE"
)

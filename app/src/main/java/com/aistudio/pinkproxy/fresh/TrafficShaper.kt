package com.aistudio.pinkproxy.fresh

import java.util.concurrent.atomic.AtomicLong

object TrafficShaper {
    private val avgRtt = AtomicLong(50L)
    
    fun updateRtt(rtt: Long) {
        if (rtt > 0) {
            val current = avgRtt.get()
            avgRtt.set((current * 7 + rtt) / 8)
        }
    }
    
    fun getRecommendedMss(): Int {
        val rtt = avgRtt.get()
        return if (rtt > 300) 1200 else 1440
    }
}

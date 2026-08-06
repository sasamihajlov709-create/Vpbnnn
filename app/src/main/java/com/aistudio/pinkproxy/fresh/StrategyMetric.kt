package com.aistudio.pinkproxy.fresh

data class StrategyMetric(val strategy: BypassStrategy, val score: Int, val successes: Long, val failures: Long, val avgRtt: Long)

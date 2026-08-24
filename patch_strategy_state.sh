sed -i 's/val ewmaLatencyMs: AtomicLong = AtomicLong(0L),/val ewmaLatencyMs: AtomicLong = AtomicLong(0L),\n    private val recentLatencies: LongArray = LongArray(100),\n    private var latencyIndex: Int = 0,\n    private var latencyCount: Int = 0,/g' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt

sed -i 's/val next = (currentEwma \* 0.8 + obs.latencyMs \* 0.2).toLong()/val next = (currentEwma \* 0.8 + obs.latencyMs \* 0.2).toLong()\n                    }\n                    synchronized(recentLatencies) {\n                        recentLatencies[latencyIndex] = obs.latencyMs\n                        latencyIndex = (latencyIndex + 1) % 100\n                        if (latencyCount < 100) latencyCount++/g' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt

cat << 'INNER_EOF' > append_p95.txt

    @Synchronized
    fun getP95Latency(): Long {
        synchronized(recentLatencies) {
            if (latencyCount == 0) return 0L
            val copy = LongArray(latencyCount)
            System.arraycopy(recentLatencies, 0, copy, 0, latencyCount)
            copy.sort()
            val p95Index = (latencyCount * 0.95).toInt().coerceAtMost(latencyCount - 1)
            return copy[p95Index]
        }
    }
INNER_EOF

sed -i '/val averageLatencyMs: Long/e cat append_p95.txt' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt

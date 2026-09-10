import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt', 'r') as f:
    text = f.read()

replacement = '''    fun recordObservation(obs: StrategyObservation) {
        sampleCount.incrementAndGet()
        
        val now = System.currentTimeMillis()
        val last = lastUsedTimestamp.get()
        
        // Aggressive temporal decay: 10% weight loss for every 10 minutes elapsed since last use, up to 90% loss
        if (last > 0 && now > last) {
            val elapsedMinutes = (now - last) / 60000.0
            val decayFactor = Math.pow(0.9, elapsedMinutes / 10.0).coerceIn(0.1, 1.0)
            if (decayFactor < 0.95) {
                weightedSuccess.set((weightedSuccess.get() * decayFactor).toLong())
                weightedFailure.set((weightedFailure.get() * decayFactor).toLong())
            }
        }
        
        lastUsedTimestamp.set(obs.timestamp)
        
        if (obs.success) {
            successCount.incrementAndGet()
            if (obs.quality >= ObservationQuality.APPLICATION_DATA_EXCHANGED) {
                verifiedSuccessCount.incrementAndGet()
            }
            
            val delta = (obs.quality.weight * 1000).toLong().coerceAtLeast(0L)
            weightedSuccess.addAndGet(delta)
'''

pattern = re.compile(r'    fun recordObservation\(obs: StrategyObservation\) \{.*?weightedSuccess.addAndGet\(delta\)', re.DOTALL)
text = pattern.sub(replacement, text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt', 'w') as f:
    f.write(text)

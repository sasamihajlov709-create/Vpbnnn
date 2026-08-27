import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt", "r") as f:
    text = f.read()

text = text.replace("val rttHistory = ConcurrentHashMap<TransportType, MutableList<Long>>()", "val rttHistory = ConcurrentHashMap<String, MutableList<Long>>()")

# Fix markSuccess
replacement1 = """    fun markSuccess(strat: BypassStrategy, transport: TransportType, host: String, latencyMs: Long = 0, quality: ObservationQuality) {
        if (latencyMs > 0) {
            val key = "${NetworkProfileManager.currentProfile.value.id}|$transport"
            val list = rttHistory.getOrPut(key) { java.util.Collections.synchronizedList(java.util.LinkedList<Long>()) }
            list.add(latencyMs)
            if (list.size > 50) list.removeAt(0)
        }"""
text = re.sub(r'    fun markSuccess.*?if \(list\.size > 50\) list\.removeAt\(0\)\n        \}', replacement1, text, flags=re.DOTALL)

# Fix getRecommendedDelay
replacement2 = """    fun getRecommendedDelay(transport: TransportType): Long {
        val intensity = BypassConfig.getIntensityForTransport(transport)
        if (intensity < 10) return 0L
        
        val key = "${NetworkProfileManager.currentProfile.value.id}|$transport"
        val history = rttHistory[key]?.let { synchronized(it) { it.toList() } } ?: emptyList()"""
text = re.sub(r'    fun getRecommendedDelay\(transport: TransportType\): Long \{.*?val history = rttHistory\[transport\]\?\.let \{ synchronized\(it\) \{ it\.toList\(\) \} \} \?: emptyList\(\)', replacement2, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt", "w") as f:
    f.write(text)

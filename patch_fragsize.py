import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt", "r") as f:
    text = f.read()

replacement = """    fun getRecommendedFragSize(transport: TransportType = TransportType.TCP): Int {
        val intensity = BypassConfig.getIntensityForTransport(transport)
        val rttKey = "${NetworkProfileManager.currentProfile.value.id}|$transport"
        val history = rttHistory[rttKey]?.let { synchronized(it) { it.toList() } } ?: emptyList()
        val avgRtt = if (history.isNotEmpty()) history.average() else 100.0

        val baseSize = when {
            intensity > 80 -> 10
            intensity > 50 -> 40
            intensity > 20 -> 100
            else -> 500
        }
        
        val adjustedSize = if (avgRtt > 300.0 && baseSize < 100) {
            baseSize * 2 
        } else if (avgRtt < 50.0 && intensity > 50) {
            (baseSize * 0.5).toInt().coerceAtLeast(5)
        } else {
            baseSize
        }
        
        return adjustedSize
    }"""

text = re.sub(r'    fun getRecommendedFragSize\(transport: TransportType = TransportType\.TCP\): Int \{.*?    \}', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt", "w") as f:
    f.write(text)

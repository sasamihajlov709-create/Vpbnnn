import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyProfileState.kt", "r") as f:
    text = f.read()

replacement = """data class StrategyMetricState(
    val score: Int = 100,
    val successCount: Int = 0,
    val failureCount: Int = 0,
    val weightedSuccess: Long = 0L,
    val weightedFailure: Long = 0L,
    val verifiedSuccessCount: Int = 0,
    val totalLatencyMs: Long = 0L,
    val recentLatencies: List<Long> = emptyList(),
    val lastUsedTimestamp: Long = 0L
) {
    fun toJsonObject(): JSONObject {
        val json = JSONObject()
        json.put("score", score)
        json.put("successCount", successCount)
        json.put("failureCount", failureCount)
        json.put("weightedSuccess", weightedSuccess)
        json.put("weightedFailure", weightedFailure)
        json.put("verifiedSuccessCount", verifiedSuccessCount)
        json.put("totalLatencyMs", totalLatencyMs)
        
        val latenciesArr = JSONArray()
        recentLatencies.forEach { latenciesArr.put(it) }
        json.put("recentLatencies", latenciesArr)
        
        json.put("lastUsedTimestamp", lastUsedTimestamp)
        return json
    }

    companion object {
        fun fromJsonObject(json: JSONObject): StrategyMetricState {
            val recentLatencies = mutableListOf<Long>()
            val arr = json.optJSONArray("recentLatencies")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    recentLatencies.add(arr.optLong(i))
                }
            }

            return StrategyMetricState(
                score = json.optInt("score", 100),
                successCount = json.optInt("successCount", 0),
                failureCount = json.optInt("failureCount", 0),
                weightedSuccess = json.optLong("weightedSuccess", 0L),
                weightedFailure = json.optLong("weightedFailure", 0L),
                verifiedSuccessCount = json.optInt("verifiedSuccessCount", 0),
                totalLatencyMs = json.optLong("totalLatencyMs", 0L),
                recentLatencies = recentLatencies,
                lastUsedTimestamp = json.optLong("lastUsedTimestamp", 0L)
            )
        }
    }
}"""

text = re.sub(r'data class StrategyMetricState\(.*?\n\}', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyProfileState.kt", "w") as f:
    f.write(text)

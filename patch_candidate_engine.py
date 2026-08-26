import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "r") as f:
    content = f.read()

select_best = """
    /**
     * Unified method for selecting the best strategy, replacing scattered logic.
     */
    fun selectBest(
        context: SelectionContext,
        excludeCurrent: BypassStrategy? = null,
        ignoreHostBlacklist: Boolean = false
    ): BypassStrategy? {
        val candidates = getEligibleCandidates(context, ignoreHostBlacklist = ignoreHostBlacklist)
        val filtered = if (excludeCurrent != null) candidates.filter { it != excludeCurrent } else candidates
        if (filtered.isEmpty()) return null
        val ranked = rankCandidatesBayesian(filtered, context)
        return ranked.firstOrNull()
    }
"""

if "fun selectBest(" not in content:
    content = content.replace("fun rankCandidatesBayesian(", select_best + "\n    fun rankCandidatesBayesian(")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt", "w") as f:
    f.write(content)

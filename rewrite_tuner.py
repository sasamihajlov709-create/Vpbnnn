import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "r") as f:
    content = f.read()

pattern = r"val candidates = listOf\([\s\S]*?\)\.filter \{[\s\S]*?System\.currentTimeMillis\(\)\)\n        \}\.distinct\(\)\.take\(4\)"
replacement = """val ctx = CandidateEngine.SelectionContext(TransportType.TCP, profileId, host, category)
        val baseList = listOf(
            currentBest,
            BypassStrategy.SNI_SPLIT,
            BypassStrategy.TLS_SNI_EXT_MANGLE,
            BypassStrategy.BYEBYEDPI_HYBRID,
            BypassStrategy.TCP_COMBINED_HYBRID,
            diverseExtreme
        )
        val candidates = CandidateEngine.getEligibleCandidates(ctx, baseList).distinct().take(4)"""

content = re.sub(pattern, replacement, content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "w") as f:
    f.write(content)


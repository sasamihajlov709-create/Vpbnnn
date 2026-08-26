with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "r") as f:
    content = f.read()

# Remove aggregateGlobalMetrics() from applyPolicyDecision
content = content.replace("        // Aggregate global metrics based on transport policies\n        aggregateGlobalMetrics()", "")

# Make aggregateGlobalMetrics public
content = content.replace("private fun aggregateGlobalMetrics()", "fun aggregateGlobalMetrics()")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "w") as f:
    f.write(content)


with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt", "r") as f:
    content = f.read()

# Add DpiPolicyEngine.aggregateGlobalMetrics() at the end of analyzeAndAdjust
content = content.replace(
    "        if (dnsSuccess + dnsFailure > 0) {\n            val dnsSuccessRate = (dnsSuccess.toDouble() / (dnsSuccess + dnsFailure) * 100)\n            val fingerprint = getCensorshipFingerprint(TransportType.DNS)\n            val decision = DpiPolicyEngine.evaluatePolicy(fingerprint, dnsSuccessRate, dnsSuccess + dnsFailure, TransportType.DNS)\n            DpiPolicyEngine.applyPolicyDecision(decision)\n        }",
    "        if (dnsSuccess + dnsFailure > 0) {\n            val dnsSuccessRate = (dnsSuccess.toDouble() / (dnsSuccess + dnsFailure) * 100)\n            val fingerprint = getCensorshipFingerprint(TransportType.DNS)\n            val decision = DpiPolicyEngine.evaluatePolicy(fingerprint, dnsSuccessRate, dnsSuccess + dnsFailure, TransportType.DNS)\n            DpiPolicyEngine.applyPolicyDecision(decision)\n        }\n\n        // Update global UI metrics exactly once per cycle\n        DpiPolicyEngine.aggregateGlobalMetrics()"
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt", "w") as f:
    f.write(content)

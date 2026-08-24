import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt", "r") as f:
    content = f.read()

content = content.replace("/* ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value - 2).coerceAtLeast(0))", "ProxyStats.updateCensorshipIntensity((ProxyStats.censorshipIntensity.value - 2).coerceAtLeast(0))")

content = content.replace(
"""        if (totalSuccess + totalFailure > 20) {
            val tcpDecision = DpiPolicyEngine.evaluatePolicy(tcpFingerprint, successRate, totalSuccess + totalFailure, TransportType.TCP)
            DpiPolicyEngine.applyPolicyDecision(tcpDecision)
        }
        
        if (totalSuccess + totalFailure > 20) {
            val udpDecision = DpiPolicyEngine.evaluatePolicy(udpFingerprint, successRate, totalSuccess + totalFailure, TransportType.UDP)
            DpiPolicyEngine.applyPolicyDecision(udpDecision)
        }""",
"""        if (totalSuccess + totalFailure > 20) {
            val tcpDecision = DpiPolicyEngine.evaluatePolicy(tcpFingerprint, successRate, totalSuccess + totalFailure, TransportType.TCP)
            val udpDecision = DpiPolicyEngine.evaluatePolicy(udpFingerprint, successRate, totalSuccess + totalFailure, TransportType.UDP)
            val dnsDecision = DpiPolicyEngine.evaluatePolicy(dnsFingerprint, successRate, totalSuccess + totalFailure, TransportType.DNS)
            
            // Apply them individually (they now write to isolated transport states inside PolicyEngine)
            DpiPolicyEngine.applyPolicyDecision(tcpDecision)
            DpiPolicyEngine.applyPolicyDecision(udpDecision)
            DpiPolicyEngine.applyPolicyDecision(dnsDecision)
        }"""
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt", "w") as f:
    f.write(content)


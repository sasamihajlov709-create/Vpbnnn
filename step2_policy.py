import os

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "r") as f:
    content = f.read()

new_policy_code = """
    data class TransportPolicyState(
        var mtu: Int = 1500,
        var isPanicMode: Boolean = false,
        var calculatedIntensity: Int = 0
    )

    val transportPolicies = java.util.concurrent.ConcurrentHashMap<TransportType, TransportPolicyState>().apply {
        put(TransportType.TCP, TransportType.TCP.let { TransportPolicyState() })
        put(TransportType.UDP, TransportType.UDP.let { TransportPolicyState() })
        put(TransportType.DNS, TransportType.DNS.let { TransportPolicyState() })
    }

    fun applyPolicyDecision(decision: PolicyDecision) {
        val policy = transportPolicies.getOrPut(decision.affectedTransport) { TransportPolicyState() }
        
        policy.calculatedIntensity = decision.targetIntensity
        
        decision.recommendedMtu?.let { newMtu ->
            policy.mtu = newMtu
        }
        
        if (decision.shouldEnterPanic) {
            policy.isPanicMode = true
            RuntimeCoordinator.requestGlobalStrategyRotation(decision.affectedTransport, "Policy Panic Trigger")
        } else {
            policy.isPanicMode = false
        }
        
        // Aggregate global metrics based on transport policies
        aggregateGlobalMetrics()

        if (decision.shouldReset) {
            resetProfileEngineStates(NetworkProfileManager.currentProfile.value.id)
        }
    }

    private fun aggregateGlobalMetrics() {
        val tcpIntensity = transportPolicies[TransportType.TCP]?.calculatedIntensity ?: 0
        val udpIntensity = transportPolicies[TransportType.UDP]?.calculatedIntensity ?: 0
        val dnsIntensity = transportPolicies[TransportType.DNS]?.calculatedIntensity ?: 0
        
        // Aggregate censorship intensity (weighted towards TCP as the most common protocol)
        val globalIntensity = (tcpIntensity * 0.5 + udpIntensity * 0.3 + dnsIntensity * 0.2).toInt()
        
        if (Math.abs(globalIntensity - ProxyStats.censorshipIntensity.value) >= 1) {
            ProxyStats.updateCensorshipIntensity(globalIntensity)
        }
    }
"""

content = content.replace("    fun applyPolicyDecision(decision: PolicyDecision) {", new_policy_code + "    fun oldApply(decision: PolicyDecision) {")
content = content.replace("fun oldApply(decision: PolicyDecision) {", "/*")
content = content.replace("    fun onDpiEventDiagnosed(type: DpiType) {", "*/\n    fun onDpiEventDiagnosed(type: DpiType) {")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "w") as f:
    f.write(content)


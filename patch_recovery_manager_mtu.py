import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "r") as f:
    content = f.read()

replacement = """
    private fun processTunnelStall(durationMs: Long, activeConns: Int, transport: TransportType) {
        val currentEsc = escalationLevel.get()
        if (currentEsc < 3) {
            _currentState.value = RecoveryState.RECONFIGURING_MTU
            RuntimeCoordinator.requestGlobalStrategyRotation(transport, "Watchdog Tunnel Stall Rotation", HostCategory.OTHER)

            // Dynamic TTL shifting
            val nextTtl = when (BypassConfig.currentTtl) {
                3 -> 5
                5 -> 8
                8 -> 10
                else -> 3
            }
            BypassConfig.setTtl(nextTtl)

            // Reduce MTU
            val currentMtu = BypassConfig.getMtuForTransport(TransportType.TCP)
            if (currentMtu > 1100) {
                val reduction = 80
                BypassConfig.setMtu(currentMtu - reduction)
                ProxyStats.logRecovery("Watchdog: Reducing MTU to ${currentMtu - reduction} due to tunnel stall")
            }
"""

content = re.sub(
    r'\s*private fun processTunnelStall\(durationMs: Long, activeConns: Int, transport: TransportType\) \{.*?\n            \}',
    replacement.lstrip('\n'),
    content,
    flags=re.DOTALL
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "w") as f:
    f.write(content)


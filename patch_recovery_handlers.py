import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "r") as f:
    content = f.read()

old_handler = """    private suspend fun processSocketStall(signal: RecoverySignal) {
        _currentState.value = RecoveryState.DEGRADED
        val transport = when (signal) {
            is RecoverySignal.TcpStall -> signal.transport
            is RecoverySignal.SslStall -> signal.transport
            else -> TransportType.TCP
        }
        val targetHost = when (signal) {
            is RecoverySignal.TcpStall -> signal.host
            is RecoverySignal.SslStall -> signal.host
            else -> null
        }
        val category = targetHost?.let { HostClassifier.classify(it) } ?: HostCategory.OTHER
        
        RuntimeCoordinator.requestGlobalStrategyRotation(transport, "Socket Stall Recovery", category, host = targetHost)"""

new_handler = """    private suspend fun processSocketStall(signal: RecoverySignal) {
        _currentState.value = RecoveryState.DEGRADED
        
        val transport = signal.transport ?: TransportType.TCP
        val targetHost = (signal as? RecoverySignal.HostLevelRecoverySignal)?.host
        val category = (signal as? RecoverySignal.HostLevelRecoverySignal)?.category ?: HostCategory.OTHER
        
        RuntimeCoordinator.requestGlobalStrategyRotation(transport, "Socket Stall Recovery", category, host = targetHost)"""

content = content.replace(old_handler, new_handler)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "w") as f:
    f.write(content)

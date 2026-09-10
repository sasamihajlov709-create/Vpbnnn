import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt', 'r') as f:
    text = f.read()

budget_code = '''
    private val recoveryTimestamps = java.util.concurrent.ConcurrentLinkedQueue<Long>()
    private fun checkRecoveryBudget(): Boolean {
        val now = System.currentTimeMillis()
        recoveryTimestamps.removeIf { now - it > 60_000L }
        if (recoveryTimestamps.size >= 4) {
            Log.w(TAG, "Recovery budget exceeded (4+ per min). Suppressing escalation to prevent loops.")
            return false
        }
        recoveryTimestamps.add(now)
        return true
    }
'''

# Insert after TAG
text = text.replace('private const val TAG = "RecoveryStateMachine"', 'private const val TAG = "RecoveryStateMachine"\n' + budget_code)

# Patch processSocketStall
stall_replacement = '''    private suspend fun processSocketStall(signal: RecoverySignal) {
        _currentState.value = RecoveryState.DEGRADED
        if (!checkRecoveryBudget()) {
            triggerActiveProbeAsync(5000L)
            return
        }
'''
text = re.sub(r'    private suspend fun processSocketStall\(signal: RecoverySignal\) \{\n        _currentState\.value = RecoveryState\.DEGRADED', stall_replacement, text)

# Patch processExtremeLatency
lat_replacement = '''    private suspend fun processExtremeLatency(latencyMs: Long, transport: TransportType) {
        _currentState.value = RecoveryState.DEGRADED
        if (!checkRecoveryBudget()) return
'''
text = re.sub(r'    private suspend fun processExtremeLatency\(latencyMs: Long, transport: TransportType\) \{\n        _currentState\.value = RecoveryState\.DEGRADED', lat_replacement, text)

# Patch processHealthDegraded
health_replacement = '''    private suspend fun processHealthDegraded(details: String, transport: TransportType) {
        _currentState.value = RecoveryState.DEGRADED
        if (!checkRecoveryBudget()) return
'''
text = re.sub(r'    private suspend fun processHealthDegraded\(details: String, transport: TransportType\) \{\n        _currentState\.value = RecoveryState\.DEGRADED', health_replacement, text)


with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt', 'w') as f:
    f.write(text)

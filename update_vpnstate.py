import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'r') as f:
    content = f.read()

target = """    private val _latestTelemetry = MutableStateFlow<ExplainableTelemetry?>(null)
    val latestTelemetry: StateFlow<ExplainableTelemetry?> = _latestTelemetry.asStateFlow()"""

replacement = """    private val _latestTelemetry = MutableStateFlow<ExplainableTelemetry?>(null)
    val latestTelemetry: StateFlow<ExplainableTelemetry?> = _latestTelemetry.asStateFlow()

    private val _isEngineProbing = MutableStateFlow(false)
    val isEngineProbing: StateFlow<Boolean> = _isEngineProbing.asStateFlow()
    
    private var engineProbingJob: kotlinx.coroutines.Job? = null
    
    fun triggerEngineProbing() {
        engineProbingJob?.cancel()
        _isEngineProbing.value = true
        engineProbingJob = kotlinx.coroutines.GlobalScope.launch {
            kotlinx.coroutines.delay(2500)
            _isEngineProbing.value = false
        }
    }"""

content = content.replace(target, replacement)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'w') as f:
    f.write(content)


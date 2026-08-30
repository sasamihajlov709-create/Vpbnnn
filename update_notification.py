import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

# I will add a notification update job
import_statement = "import kotlinx.coroutines.flow.collectLatest\n"
if "collectLatest" not in content:
    content = content.replace("import kotlinx.coroutines.launch", "import kotlinx.coroutines.launch\nimport kotlinx.coroutines.flow.collectLatest")

new_func = """    private var notificationJob: Job? = null
    
    private fun startDynamicNotification() {
        notificationJob?.cancel()
        notificationJob = serviceScope.launch {
            kotlinx.coroutines.flow.combine(
                BypassConfig.strategy,
                ProxyStats.activeFlows,
                ProxyStats.censorshipIntensity
            ) { strat, flows, intensity ->
                val activeCount = flows.size
                val panic = if (intensity > 50) " | PANIC" else ""
                val subtext = "Str: ${strat.name} | Active: $activeCount$panic"
                subtext
            }.collectLatest { subtext ->
                if (isVpnRunning()) {
                    notificationController.showNotification("Engine Active", subtext)
                }
            }
        }
    }
    
    private fun stopDynamicNotification() {
        notificationJob?.cancel()
        notificationJob = null
    }"""

content = content.replace("private var isStopping = false", new_func + "\n    private var isStopping = false")

content = content.replace("startVpnInternal() {", "startVpnInternal() {\n        startDynamicNotification()")
content = content.replace("stopVpnInternal() {", "stopVpnInternal() {\n        stopDynamicNotification()")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)

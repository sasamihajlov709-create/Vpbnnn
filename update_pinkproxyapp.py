import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'r') as f:
    content = f.read()

target = """    val activeStrategy by BypassConfig.tcpStrategy.collectAsStateWithLifecycle(initialValue = null)
    val testingStrategies by BypassConfig.testingStrategies.collectAsStateWithLifecycle(initialValue = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.SNI_TRIPLE, BypassStrategy.BYEBYEDPI_SIM))
    val signalQuality by ProxyStats.signalQuality.collectAsStateWithLifecycle(initialValue = 100)"""

replacement = """    val activeStrategy by BypassConfig.tcpStrategy.collectAsStateWithLifecycle(initialValue = null)
    val metrics by BypassConfig.strategyMetrics.collectAsStateWithLifecycle(initialValue = emptyList())
    val staticTesting by BypassConfig.testingStrategies.collectAsStateWithLifecycle(initialValue = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.SNI_TRIPLE, BypassStrategy.BYEBYEDPI_SIM))
    val testingStrategies = remember(metrics, staticTesting) {
        if (metrics.isEmpty()) staticTesting else metrics.take(6).map { it.strategy }
    }
    val signalQuality by ProxyStats.signalQuality.collectAsStateWithLifecycle(initialValue = 100)"""

content = content.replace(target, replacement)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'w') as f:
    f.write(content)


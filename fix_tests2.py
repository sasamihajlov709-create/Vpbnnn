import os
import re

def process_file(path, fixes):
    if not os.path.exists(path): return
    with open(path, "r") as f:
        content = f.read()
    
    for fix in fixes:
        content = content.replace(fix[0], fix[1])
        
    with open(path, "w") as f:
        f.write(content)

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/DnsCachePersistenceTest.kt", [
    ("BypassConfig.getSessionConfig(host, strategy = BypassStrategy.SNI_SPLIT, rtt = 400L)", "BypassConfig.getSessionConfig(host, strategy = BypassStrategy.SNI_SPLIT, rtt = 400L, transport = com.aistudio.pinkproxy.fresh.TransportType.TCP)")
])

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachineTest.kt", [
    ("RecoverySignal.TunnelStall(durationMs = 15000, activeConnections = 3)", "RecoverySignal.TunnelStall(durationMs = 15000, activeConnections = 3, transport = com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("RecoverySignal.ExtremeLatency(3500)", "RecoverySignal.ExtremeLatency(3500, com.aistudio.pinkproxy.fresh.TransportType.TCP)")
])

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/ServiceCheckerAndStatusTest.kt", [
    ("StabilityAnalyzer.recordEvent(isFailure = true)", "StabilityAnalyzer.recordEvent(isFailure = true, transport = com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("StabilityAnalyzer.recordEvent(isFailure = false, rtt = 120L)", "StabilityAnalyzer.recordEvent(isFailure = false, rtt = 120L, transport = com.aistudio.pinkproxy.fresh.TransportType.TCP)")
])

# For UiRenderAndMetricsStressTest.kt, we'll just read and replace line 77 or Regex
with open("app/src/test/java/com/aistudio/pinkproxy/fresh/UiRenderAndMetricsStressTest.kt", "r") as f:
    content = f.read()
content = content.replace("RuntimeCoordinator.requestGlobalStrategyRotation(", "RuntimeCoordinator.requestGlobalStrategyRotation(transport = com.aistudio.pinkproxy.fresh.TransportType.TCP, ")
with open("app/src/test/java/com/aistudio/pinkproxy/fresh/UiRenderAndMetricsStressTest.kt", "w") as f:
    f.write(content)


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

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/BypassConfigAndLifecycleIntegrationTest.kt", [
    ("BypassConfig.setStrategy(BypassStrategy.DIRECT)", "BypassConfig.setStrategy(BypassStrategy.DIRECT, com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("BypassConfig.setStrategy(BypassStrategy.UDP_COMBINED_NUCLEAR)", "BypassConfig.setStrategy(BypassStrategy.UDP_COMBINED_NUCLEAR, com.aistudio.pinkproxy.fresh.TransportType.UDP)"),
    ("BypassConfig.setStrategy(BypassStrategy.SNI_SPLIT)", "BypassConfig.setStrategy(BypassStrategy.SNI_SPLIT, com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("BypassConfig.getSessionConfig(\"example.com\", BypassStrategy.SNI_TRIPLE, 50L)", "BypassConfig.getSessionConfig(\"example.com\", BypassStrategy.SNI_TRIPLE, 50L, com.aistudio.pinkproxy.fresh.TransportType.TCP)")
])

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/DnsCachePersistenceTest.kt", [
    ("BypassConfig.getSessionConfig(domain, BypassStrategy.DIRECT, 0L)", "BypassConfig.getSessionConfig(domain, BypassStrategy.DIRECT, 0L, com.aistudio.pinkproxy.fresh.TransportType.TCP)")
])

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/RecoveryPipelineIntegrationTest.kt", [
    ("DpiAnalyzer.recordEvent(DpiType.TLS_SNI_BLOCK)", "DpiAnalyzer.recordEvent(DpiType.TLS_SNI_BLOCK, com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("DpiAnalyzer.recordEvent(DpiType.TCP_RESET)", "DpiAnalyzer.recordEvent(DpiType.TCP_RESET, com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("DpiAnalyzer.getCensorshipFingerprint()", "DpiAnalyzer.getCensorshipFingerprint(com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("val decision = DpiPolicyEngine.evaluatePolicy(", "val decision = DpiPolicyEngine.evaluatePolicy(transport = com.aistudio.pinkproxy.fresh.TransportType.TCP,")
])

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachineTest.kt", [
    ("RecoverySignal.DpiDetected(DpiType.TCP_RESET, host)", "RecoverySignal.DpiDetected(DpiType.TCP_RESET, host, com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("RecoverySignal.DpiDetected(DpiType.TLS_SNI_BLOCK, host)", "RecoverySignal.DpiDetected(DpiType.TLS_SNI_BLOCK, host, com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("RecoverySignal.ProxyUnresponsive(\"Test timeout\")", "RecoverySignal.ProxyUnresponsive(\"Test timeout\", com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("RecoverySignal.ExtremeLatency(3000)", "RecoverySignal.ExtremeLatency(3000, com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("RecoverySignal.HealthDegraded(\"High failure rate\")", "RecoverySignal.HealthDegraded(\"High failure rate\", com.aistudio.pinkproxy.fresh.TransportType.TCP)")
])

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/ServiceCheckerAndStatusTest.kt", [
    ("RecoverySignal.HealthDegraded(\"Service Unreachable\")", "RecoverySignal.HealthDegraded(\"Service Unreachable\", com.aistudio.pinkproxy.fresh.TransportType.TCP)"),
    ("RecoverySignal.TunnelStall(12000, 0)", "RecoverySignal.TunnelStall(12000, 0, com.aistudio.pinkproxy.fresh.TransportType.TCP)")
])

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/TransportSpecificRecoveryTest.kt", [
    ("BypassConfig.setGlobalStrategy(initialTcpStrategy)", "BypassConfig.setStrategy(initialTcpStrategy, com.aistudio.pinkproxy.fresh.TransportType.TCP)")
])

process_file("app/src/test/java/com/aistudio/pinkproxy/fresh/UiRenderAndMetricsStressTest.kt", [
    ("RuntimeCoordinator.requestGlobalStrategyRotation(", "RuntimeCoordinator.requestGlobalStrategyRotation(transport = com.aistudio.pinkproxy.fresh.TransportType.TCP, ")
])

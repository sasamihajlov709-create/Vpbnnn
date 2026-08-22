import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'r') as f:
    content = f.read()

# Restore the correct parameters for the success recordResult
replacement_success = """DpiStrategySelector.recordResult(
                                strategy = strategy,
                                success = true,
                                transport = TransportType.TCP,
                                category = HostClassifier.classify(host),
                                host = host,
                                latencyMs = latency,
                                quality = ObservationQuality.TLS_RECORD_RECEIVED
                            )"""

# The first one was replaced with the dummy placeholder from the previous script
content = re.sub(r'DpiStrategySelector\.recordResult\(\s*strategy = strategy,\s*success = success_placeholder,\s*transport = TransportType\.TCP,\s*category = HostClassifier\.classify\(host\),\s*host = host,\s*latencyMs = latencyMs_placeholder,\s*quality = ObservationQuality\.TLS_RECORD_RECEIVED\s*\)', replacement_success, content, count=1)

# Restore the correct parameters for the failure recordResult
replacement_fail = """DpiStrategySelector.recordResult(
            strategy = strategy,
            success = false,
            transport = TransportType.TCP,
            category = HostClassifier.classify(host),
            host = host,
            latencyMs = 0L,
            reason = FailureReason.TIMEOUT,
            quality = ObservationQuality.CONNECT_ONLY
        )"""
content = re.sub(r'DpiStrategySelector\.recordResult\(\s*strategy = strategy,\s*success = success_placeholder,\s*transport = TransportType\.TCP,\s*category = HostClassifier\.classify\(host\),\s*host = host,\s*latencyMs = latencyMs_placeholder,\s*quality = ObservationQuality\.TLS_RECORD_RECEIVED\s*\)', replacement_fail, content, count=1)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'w') as f:
    f.write(content)

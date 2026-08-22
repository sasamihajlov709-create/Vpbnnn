import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'r') as f:
    content = f.read()

# ProactiveAutoTuner syntax errors. "Argument already passed for this parameter." "val cannot be reassigned".
# Let's fix recordResult properly by finding where it was mangled.
# The mangled recordResult looks like:
# DpiStrategySelector.recordResult(
#                                strategy = strategy,
#                                success = true,
#                                transport = TransportType.TCP,
#                                category = HostClassifier.classify(host),
#                                host = host,
#                                latencyMs = latency,
#                                quality = ObservationQuality.TLS_RECORD_RECEIVED
#                            )
# Wait, the error is:
# 138:30 Syntax error: Unexpected tokens (use ';' to separate expressions on the same line).
# 139:33 'val' cannot be reassigned.
# 140:33 Unresolved reference 'latencyMs'.
# Ah, I replaced something incorrectly, likely deleting the opening parenthesis.

content = re.sub(r'DpiStrategySelector\.recordResult.*?quality = ObservationQuality\.TLS_RECORD_RECEIVED.*?\}', 
r'''DpiStrategySelector.recordResult(
                                strategy = strategy,
                                success = true,
                                transport = TransportType.TCP,
                                category = HostClassifier.classify(host),
                                host = host,
                                latencyMs = latency,
                                quality = ObservationQuality.TLS_RECORD_RECEIVED
                            )
                        }''', content, flags=re.DOTALL, count=1)

content = re.sub(r'DpiStrategySelector\.recordResult.*?quality = ObservationQuality\.CONNECT_ONLY.*?\}', 
r'''DpiStrategySelector.recordResult(
            strategy = strategy,
            success = false,
            transport = TransportType.TCP,
            category = HostClassifier.classify(host),
            host = host,
            latencyMs = 0L,
            reason = FailureReason.TIMEOUT,
            quality = ObservationQuality.CONNECT_ONLY
        )''', content, flags=re.DOTALL, count=1)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'w') as f:
    f.write(content)

# Fix HostCategory.GENERIC to HostCategory.DEFAULT in RecoveryStateMachine.
# The enum might not have GENERIC. The error was unresolved reference 'GENERIC'
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt', 'r') as f:
    rec = f.read()
rec = re.sub(r'HostCategory\.GENERIC', r'HostCategory.DEFAULT', rec)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt', 'w') as f:
    f.write(rec)

# Check DpiEngine syntax errors:
# 238:201 Only expressions are allowed in this context
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    dpi = f.read()

# Let's clean up markSuccess and markFailure in DpiEngine completely.
dpi_success = """    fun markSuccess(strat: BypassStrategy, transport: TransportType, host: String, latencyMs: Long = 0, quality: ObservationQuality = ObservationQuality.SUSTAINED_DATA_TRANSFER) {
        val category = HostClassifier.classify(host)
        DpiStrategySelector.recordResult(
            strategy = strat,
            success = true,
            transport = transport,
            category = category,
            latencyMs = latencyMs,
            host = host,
            quality = quality
        )
    }"""
dpi_fail = """    fun markFailure(
        strat: BypassStrategy, 
        transport: TransportType,
        host: String, 
        latencyMs: Long = 0,
        reason: FailureReason? = null,
        quality: ObservationQuality = ObservationQuality.CONNECT_ONLY
    ) {
        val category = HostClassifier.classify(host)
        DpiStrategySelector.recordResult(
            strategy = strat,
            success = false,
            transport = transport,
            category = category,
            reason = reason,
            latencyMs = latencyMs,
            host = host,
            quality = quality
        )
    }"""

# I need to find where markSuccess and markFailure are defined and replace them entirely.
dpi = re.sub(r'    fun markSuccess.*?(?=    fun markFailure)', dpi_success + "\n\n", dpi, flags=re.DOTALL)
dpi = re.sub(r'    fun markFailure.*?(?=    fun recordStrategyResult)', dpi_fail + "\n\n", dpi, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
    f.write(dpi)


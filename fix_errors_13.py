import re

kt_files = [
    'app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt',
    'app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt',
    'app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt'
]

for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()
    
    # In RecoveryStateMachine: `requestGlobalStrategyRotation` missing category
    # Signature is: requestGlobalStrategyRotation(transport: TransportType, reason: String, category: HostCategory)
    if 'RecoveryStateMachine' in f:
        # Default to HostCategory.DEFAULT if we don't have host
        content = re.sub(r'RuntimeCoordinator\.requestGlobalStrategyRotation\(([^,]+),\s*"([^"]+)"\)', r'RuntimeCoordinator.requestGlobalStrategyRotation(\1, "\2", HostCategory.DEFAULT)', content)
        # Fix specific error where `targetHost` is null checked
        content = re.sub(r'if \(targetHost \!= null\) \{\s*\}', r'if (targetHost != null) {\n                        RuntimeCoordinator.requestGlobalStrategyRotation(transport, "DPI Signal Escalation", HostClassifier.classify(targetHost))\n                    }', content)

    if 'ProactiveAutoTuner' in f:
        # In ProactiveAutoTuner, recordResult needs `category` not `hostCategory`? Let's check recordResult signature.
        # recordResult(strategy: BypassStrategy, success: Boolean, transport: TransportType, category: HostCategory, ...)
        # add category if missing.
        content = re.sub(r'DpiStrategySelector\.recordResult\(\s*host = host,\s*strategy = strategy,\s*success = (true|false),\s*latencyMs = (.*?),', r'DpiStrategySelector.recordResult(\n                                strategy = strategy,\n                                success = \1,\n                                transport = TransportType.TCP,\n                                category = HostClassifier.classify(host),\n                                host = host,\n                                latencyMs = \2,', content)

    with open(f, 'w') as file:
        file.write(content)


import re
import glob

kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()

    # DpiEngine: markSuccess / markFailure don't exist anymore because they are in DpiStrategySelector or renamed?
    # Wait, earlier I deleted markSuccess and markFailure from DpiEngine entirely?
    # No, I rewrote DpiEngine and it HAS markSuccess and markFailure. But wait, I might have messed up the visibility or name.
    # Ah, I replaced recordStrategyResult with DpiEngine.recordStrategyResult.
    
    # ProactiveAutoTuner / TcpRaceConnector etc -> DpiStrategySelector.recordResult
    content = re.sub(r'DpiEngine\.recordStrategyResult\(', r'DpiStrategySelector.recordResult(', content)

    # RecoveryStateMachine -> escalateHostStrategy to requestGlobalStrategyRotation
    content = re.sub(r'RuntimeCoordinator\.escalateHostStrategy\(', r'RuntimeCoordinator.requestGlobalStrategyRotation(', content)
    
    # DpiEngine `category = category` passed to recordResult/markFailure/etc. I removed it from markFailure in DpiEngine?
    # Let's just bypass DpiEngine for recording and use DpiStrategySelector.recordResult directly everywhere.
    content = re.sub(r'DpiEngine\.markSuccess\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)', r'DpiStrategySelector.recordResult(strategy = \1, success = true, transport = \2, host = \3, latencyMs = \4, quality = \5)', content)
    
    content = re.sub(r'DpiEngine\.markFailure\(([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^)]+)\)', r'DpiStrategySelector.recordResult(strategy = \1, success = false, transport = \2, host = \3, latencyMs = \4, reason = \5, quality = \6)', content)

    # ProactiveAutoTuner: getFallbackStrategy instead of getDiverseFallback
    content = re.sub(r'DpiStrategySelector\.getDiverseFallback\(', r'DpiStrategySelector.getFallbackStrategy(', content)
    
    with open(f, 'w') as file:
        file.write(content)


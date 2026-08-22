import re
import glob

kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()

    # Fix specific argument name from `strat` to `strategy` everywhere inside `recordResult`
    content = re.sub(r'strat\s*=', r'strategy =', content)
    
    # In RecoveryStateMachine, RuntimeCoordinator requestGlobalStrategyRotation takes (transport, reason, category, profileId)
    # The error says "requestGlobalStrategyRotation(TransportType.TCP, "TCP Reset detected", host)"
    # HostCategory != String
    content = re.sub(r'RuntimeCoordinator\.requestGlobalStrategyRotation\(([^,]+),\s*([^,]+),\s*host\)', r'RuntimeCoordinator.requestGlobalStrategyRotation(\1, \2, HostClassifier.classify(host))', content)
    content = re.sub(r'RuntimeCoordinator\.requestGlobalStrategyRotation\(([^,]+),\s*([^,]+),\s*targetHost\)', r'RuntimeCoordinator.requestGlobalStrategyRotation(\1, \2, HostClassifier.classify(targetHost!!))', content)

    # In ProactiveAutoTuner `val category = HostCategory.valueOf(category)` ? No `HostClassifier.classify(host)`
    content = re.sub(r'DpiStrategySelector\.getBestStrategy\(\s*category = ([^,]+),\s*category = ([^,]+)', r'DpiStrategySelector.getBestStrategy(category = \2', content)

    with open(f, 'w') as file:
        file.write(content)


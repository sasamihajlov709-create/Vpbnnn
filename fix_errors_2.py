import re
import glob

# 1. getAverageScore parameter mismatch
kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()
    
    # DpiStrategySelector.getAverageScore(strategy, category) -> DpiStrategySelector.getAverageScore(strategy)
    content = re.sub(r'DpiStrategySelector\.getAverageScore\(([^,]+),\s*[^)]+\)', r'DpiStrategySelector.getAverageScore(\1)', content)
    
    # recordStrategyResult
    content = re.sub(r'DpiStrategySelector\.recordStrategyResult\(([^,]+),\s*false', r'DpiEngine.markFailure(\1', content)
    content = re.sub(r'DpiStrategySelector\.recordStrategyResult\(([^,]+),\s*true', r'DpiEngine.markSuccess(\1', content)
    content = re.sub(r'DpiStrategySelector\.recordResult\(([^,]+),\s*false', r'DpiEngine.markFailure(\1', content)
    content = re.sub(r'DpiStrategySelector\.recordResult\(([^,]+),\s*true', r'DpiEngine.markSuccess(\1', content)
    
    content = re.sub(r'DpiEngine\.recordStrategyResult\(([^,]+),\s*false', r'DpiEngine.markFailure(\1', content)
    content = re.sub(r'DpiEngine\.recordStrategyResult\(([^,]+),\s*true', r'DpiEngine.markSuccess(\1', content)
    content = re.sub(r'DpiEngine\.recordResult\(([^,]+),\s*false', r'DpiEngine.markFailure(\1', content)
    content = re.sub(r'DpiEngine\.recordResult\(([^,]+),\s*true', r'DpiEngine.markSuccess(\1', content)
    
    # getFallbackStrategy parameter mismatch
    # Old getDiverseFallback signature was (strategy, category, transport) or similar. 
    # New getFallbackStrategy signature is (strategy, transport). 
    # Actually wait, old getDiverseFallback took (strategy, category).
    content = re.sub(r'DpiStrategySelector\.getFallbackStrategy\(([^,]+),\s*[^,]+,\s*([^)]+)\)', r'DpiStrategySelector.getFallbackStrategy(\1, \2)', content)
    # If it was 2 parameters but the 2nd is a category instead of transport:
    # Most places call it with transport as last parameter or didn't pass transport. We'll fix manually if needed.
    
    # escalateHostStrategy -> rotateGlobalStrategy
    content = re.sub(r'RuntimeCoordinator\.escalateHostStrategy\(', r'RuntimeCoordinator.rotateGlobalStrategy(', content)
    
    # VpnShutdownCoordinator synchronous=true issue
    content = re.sub(r'DpiStorage\.saveProfileScores\(synchronous = true\)', r'DpiStorage.saveProfileScores(context, NetworkProfileManager.currentProfile.value.id)', content)
    content = re.sub(r'DpiStorage\.saveProfileScores\(true\)', r'DpiStorage.saveProfileScores(context, NetworkProfileManager.currentProfile.value.id)', content)
    
    # isBlacklisted parameter mismatch
    content = re.sub(r'\(\(DpiEngine\.circuitBreakers\[([^\]]+)\] \?\: 0L\) > System\.currentTimeMillis\(\)\),\s*[^)]+\)', r'((DpiEngine.circuitBreakers[\1] ?: 0L) > System.currentTimeMillis())', content)
    
    with open(f, 'w') as file:
        file.write(content)

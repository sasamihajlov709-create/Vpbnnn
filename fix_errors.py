import re
import os

def replace_in_file(filepath, pattern, replacement):
    with open(filepath, 'r') as f:
        content = f.read()
    content = re.sub(pattern, replacement, content)
    with open(filepath, 'w') as f:
        f.write(content)

# 1. DpiEngine.kt - NetworkProfileManager.getCurrentProfile()
replace_in_file('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 
                r'NetworkProfileManager\.getCurrentProfile\(\)', 
                r'NetworkProfileManager.currentProfile.value')

# 2. DpiStorage.kt - NetworkProfileManager.getCurrentProfile()
replace_in_file('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStorage.kt', 
                r'NetworkProfileManager\.getCurrentProfile\(\)', 
                r'NetworkProfileManager.currentProfile.value')

# 3. PinkVpnService.kt - switchNetworkProfile
replace_in_file('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt',
                r'private fun switchNetworkProfile',
                r'fun switchNetworkProfile')
replace_in_file('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt',
                r'DpiEngine\.switchNetworkProfile',
                r'DpiEngine.switchNetworkProfile')

# 4. Replace recordStrategyResult with markFailure / markSuccess
import glob
kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    if f.endswith('DpiEngine.kt') or f.endswith('DpiStrategySelector.kt'): continue
    
    with open(f, 'r') as file:
        content = file.read()
        
    content = re.sub(r'DpiStrategySelector\.recordResult\(([^,]+),\s*false', r'DpiEngine.markFailure(\1', content)
    content = re.sub(r'DpiStrategySelector\.recordResult\(([^,]+),\s*true', r'DpiEngine.markSuccess(\1', content)
    content = re.sub(r'DpiEngine\.recordResult\(([^,]+),\s*false', r'DpiEngine.markFailure(\1', content)
    content = re.sub(r'DpiEngine\.recordResult\(([^,]+),\s*true', r'DpiEngine.markSuccess(\1', content)
    
    content = re.sub(r'DpiEngine\.recordStrategyResult\(([^,]+),\s*false', r'DpiEngine.markFailure(\1', content)
    content = re.sub(r'DpiEngine\.recordStrategyResult\(([^,]+),\s*true', r'DpiEngine.markSuccess(\1', content)
    
    # 5. getDiverseFallback -> getFallbackStrategy
    content = re.sub(r'DpiStrategySelector\.getDiverseFallback\(', r'DpiStrategySelector.getFallbackStrategy(', content)
    content = re.sub(r'DpiEngine\.getDiverseFallback\(', r'DpiStrategySelector.getFallbackStrategy(', content)
    
    # 6. isBlacklisted -> circuitBreakers check
    # Actually just replace `DpiEngine.isBlacklisted(strat)` with `(DpiEngine.circuitBreakers[strat] ?: 0L) > System.currentTimeMillis()`
    content = re.sub(r'DpiEngine\.isBlacklisted\(([^)]+)\)', r'((DpiEngine.circuitBreakers[\1] ?: 0L) > System.currentTimeMillis())', content)
    
    # 7. selectStrategy -> getBestStrategy
    content = re.sub(r'DpiStrategySelector\.selectStrategy\(', r'DpiStrategySelector.getBestStrategy(', content)
    content = re.sub(r'DpiEngine\.selectStrategy\(', r'DpiStrategySelector.getBestStrategy(', content)
    
    # 8. saveScores -> saveProfileScores
    content = re.sub(r'DpiStorage\.saveScores\(', r'DpiStorage.saveProfileScores(', content)
    
    # 9. escalateHostStrategy
    content = re.sub(r'RuntimeCoordinator\.escalateHostStrategy\(', r'RuntimeCoordinator.rotateGlobalStrategy(', content)
    
    # 10. getWeightedScore -> getAverageScore
    content = re.sub(r'DpiStrategySelector\.getWeightedScore\(', r'DpiStrategySelector.getAverageScore(', content)

    with open(f, 'w') as file:
        file.write(content)


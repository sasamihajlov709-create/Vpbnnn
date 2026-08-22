import re
import glob

# The script `fix_errors_7.py` replaced `strat =` with `strategy =` EVERYWHERE, which broke internal variables named `strat`.
# Let's revert that and do it correctly.

kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()

    # Revert `strategy =` back to `strat =` except in `recordResult`
    # Actually, the easiest is to just revert `strategy =` -> `strat =` where the context is NOT DpiStrategySelector.recordResult.
    # No, the easiest is to just replace ALL `val strategy =` back to `val strat =` if we accidentally replaced variable names.
    # But wait, `strat\s*=` matched assignments like `strat = mem.strategy`.
    content = re.sub(r'strategy =', r'strat =', content)

    # Now carefully fix `recordResult` only.
    content = re.sub(r'DpiStrategySelector\.recordResult\((.*?)\)', 
                     lambda m: 'DpiStrategySelector.recordResult(' + re.sub(r'\bstrat\b\s*=', 'strategy =', m.group(1)) + ')', 
                     content, flags=re.DOTALL)
    
    # Same for DpiEngine.markSuccess/Failure (although they don't use named args maybe, let's fix just in case)
    # Actually, in ProactiveAutoTuner: DpiStrategySelector.getBestStrategy -> change category = category to category = HostClassifier.classify(host)
    content = re.sub(r'DpiStrategySelector\.getBestStrategy\(\s*category = category,\s*host = host,\s*transport = TransportType.TCP\)', 
                     r'DpiStrategySelector.getBestStrategy(category = HostClassifier.classify(host), host = host, transport = TransportType.TCP)', content)

    # In ProactiveAutoTuner: DpiStrategySelector.recordResult(host = host, strat = strat, failed = false)
    # Re-fix success/failure naming.
    content = re.sub(r'failed\s*=\s*false', r'success = true', content)
    content = re.sub(r'failed\s*=\s*true', r'success = false', content)

    # In VpnShutdownCoordinator:
    content = re.sub(r'DpiStorage\.saveProfileScores\(context,\s*synchronous\s*=\s*true\)', r'DpiStorage.saveProfileScores(context, NetworkProfileManager.currentProfile.value.id)', content)
    
    with open(f, 'w') as file:
        file.write(content)

# And fix DpiEngine parameter declarations which might have been ruined
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    dpi = f.read()

dpi = re.sub(r'fun markSuccess\(strat: BypassStrategy,', r'fun markSuccess(strat: BypassStrategy,', dpi)
dpi = re.sub(r'fun markFailure\(\s*strat: BypassStrategy,', r'fun markFailure(\n        strat: BypassStrategy,', dpi)

# Clean up DpiEngine markSuccess / markFailure body if they were ruined:
dpi = re.sub(r'strategy = strat =', r'strategy = strat,', dpi) # just in case

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
    f.write(dpi)


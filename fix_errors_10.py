import re
import glob

# The problem is that the script `fix_errors_8.py` was too aggressive and blindly replaced `strategy =` with `strat =` everywhere EXCEPT where it matched `DpiStrategySelector.recordResult`.
# But `StrategyExecutionRegistry`, `BypassConfig.applyInternalStrategy`, and many other places use `strategy` as a parameter name in data classes or function calls.
# It broke a LOT of data class initializations (e.g. `StrategyMetric(strategy = strat)` became `StrategyMetric(strat = strat)`).

# Let's fix this by finding all data classes and fixing the parameter names back.
# Actually, the safest way is to change EVERY `strat =` back to `strategy =`.
# Wait, if we change `strat =` back to `strategy =`, what about the local variables?
# Kotlin data class `val strategy: BypassStrategy` means named parameter is `strategy = `. 

kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()

    # Revert `strat =` to `strategy =` everywhere, since parameter names for BypassStrategy are universally `strategy` in this codebase.
    content = re.sub(r'\bstrat\s*=', r'strategy =', content)

    # In ProactiveAutoTuner: DpiStrategySelector.recordResult(host = host, strat = strat, failed = false)
    # Re-fix success/failure naming.
    content = re.sub(r'failed\s*=\s*false', r'success = true', content)
    content = re.sub(r'failed\s*=\s*true', r'success = false', content)

    # In VpnShutdownCoordinator:
    content = re.sub(r'DpiStorage\.saveProfileScores\(context,\s*synchronous\s*=\s*true\)', r'DpiStorage.saveProfileScores(context, NetworkProfileManager.currentProfile.value.id)', content)
    
    with open(f, 'w') as file:
        file.write(content)

# DpiEngine parameters
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    dpi = f.read()

dpi = re.sub(r'fun markSuccess\(\s*strategy:\s*BypassStrategy', r'fun markSuccess(strat: BypassStrategy', dpi)
dpi = re.sub(r'fun markFailure\(\n\s*strategy:\s*BypassStrategy', r'fun markFailure(\n        strat: BypassStrategy', dpi)
dpi = re.sub(r'fun recordStrategyResult\(\n\s*strategy:\s*BypassStrategy', r'fun recordStrategyResult(\n        strat: BypassStrategy', dpi)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
    f.write(dpi)

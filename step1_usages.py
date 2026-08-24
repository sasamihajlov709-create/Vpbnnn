import os
import glob
import re

files = glob.glob("app/src/main/java/com/aistudio/pinkproxy/fresh/**/*.kt", recursive=True)

for file in files:
    with open(file, "r") as f:
        content = f.read()
    
    modified = False

    # DpiEngine removal
    if "DpiEngine.kt" in file:
        content = re.sub(r"val circuitBreakers = ConcurrentHashMap<BypassStrategy, Long>\(\)\s*", "", content)
        content = re.sub(r"val consecutiveFailures = ConcurrentHashMap<BypassStrategy, AtomicInteger>\(\)\s*", "", content)
        content = re.sub(r"circuitBreakers\.clear\(\)\s*", "", content)
        content = re.sub(r"consecutiveFailures\.clear\(\)\s*", "", content)
        content = re.sub(r"StrategyStateRepository\.consecutiveFailuresByHost\.clear\(\)\s*", "", content)
        modified = True

    if "DpiPolicyEngine.kt" in file:
        content = re.sub(r"DpiEngine\.circuitBreakers\.clear\(\)\s*", "", content)
        content = re.sub(r"DpiEngine\.consecutiveFailures\.clear\(\)\s*", "", content)
        modified = True

    if modified:
        with open(file, "w") as f:
            f.write(content)


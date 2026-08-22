import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    dpi = f.read()

# Fix DpiEngine.kt Syntax error: Missing '} on line 163.
# The previous script stripped too much from DpiEngine.kt
# Since we don't have git, I'll have to fix the curly braces manually.

# Wait, `initStrategyChains` and `triggerMicroProbe` and `pruneStrategies` were unresolved because they were in DpiEngine and were deleted?
# Yes, because the replacement in fix_errors_16.py:
# `dpi = re.sub(r'    fun markFailure.*?(?=    fun recordStrategyResult)', dpi_fail + "\n\n", dpi, flags=re.DOTALL)`
# Wait, `markFailure` didn't have `recordStrategyResult` directly after it in the old version maybe?
# Or `markSuccess` didn't have `markFailure` directly after it?
# Let's see what methods are missing. initStrategyChains, triggerMicroProbe, pruneStrategies.
# They were likely between markSuccess and markFailure, or deleted entirely.

# Let's check DpiAnalyzer.kt: Syntax errors 133:38
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'r') as f:
    analyzer = f.read()

# Let's fix DpiAnalyzer first.
analyzer = re.sub(r'            DpiEngine\.categoryWeightedSuccessHistory\.values\.forEach \{ catMap ->.*?\n            \}', '', analyzer, flags=re.DOTALL)
analyzer = re.sub(r'            DpiEngine\.weightedSuccessHistory\.forEach \{ \(_, count\) -> count\.updateAndGet \{ \(it \* 0\.5\)\.toLong\(\) \} \}', '', analyzer)
analyzer = re.sub(r'            DpiEngine\.successHistory\.forEach \{ \(_, count\) -> count\.updateAndGet \{ \(it \* 0\.5\)\.toInt\(\) \} \}', '', analyzer)
analyzer = re.sub(r'            DpiEngine\.failureHistory\.forEach \{ \(_, count\) -> count\.updateAndGet \{ \(it \* 0\.5\)\.toInt\(\) \} \}', '', analyzer)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'w') as f:
    f.write(analyzer)

# For ProactiveAutoTuner:
# 111:9 Return type mismatch: expected 'Boolean', actual 'Unit'
# 140:2 Syntax error: Expecting '}'.
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'r') as f:
    tuner = f.read()

tuner = re.sub(r'quality = ObservationQuality\.TLS_RECORD_RECEIVED\n\s*\)\n\s*\}', 
r'''quality = ObservationQuality.TLS_RECORD_RECEIVED
                            )''', tuner)
# We need to make sure tuneHost returns Boolean if it used to? Wait, tuneHost is `private suspend fun tuneHost`. 

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'w') as f:
    f.write(tuner)


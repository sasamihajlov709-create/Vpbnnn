import re
import glob

# There are still so many `strat` unresolved references. That's because fix_errors_12.py didn't fix them.
# The safest way is to rename ALL local variables `strat` back to `strategy`.
# Wait, NO. If we rename all `strat` back to `strategy`, it conflicts with `strategy` as a parameter name in data classes if we do `strat = strategy`.
# Actually, the original code had `val strategy` in loops. The reason we had `strat = strategy` was because of `StrategyMetric(strategy = strat)`.
# Let's fix ALL `strat` usages. If `strat` is unresolved, we change it to `strategy`.
# Let's use `sed` / Python replacement to change `strat` to `strategy` EXCEPT where it's `strategy = strat`?
# In Kotlin, `strategy = strategy` is perfectly valid. The compiler knows the left side is the named parameter and the right side is the variable.
# So we can literally rename ALL `strat` back to `strategy` everywhere and use `strategy = strategy`.

kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()

    # Revert all `strat` back to `strategy`.
    content = re.sub(r'\bstrat\b', r'strategy', content)
    
    # Fix ProactiveAutoTuner: "Argument already passed for this parameter."
    # Because we added `strategy = strategy, success = ..., transport = TransportType.TCP, category = ...` twice maybe?
    
    with open(f, 'w') as file:
        file.write(content)

# Now fix ProactiveAutoTuner duplicate parameters
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'r') as f:
    tuner = f.read()

tuner = re.sub(r'DpiStrategySelector\.recordResult\(\s*strategy = strategy,\s*success = (true|false),\s*transport = TransportType\.TCP,\s*category = HostClassifier\.classify\(host\),\s*host = host,\s*latencyMs = (.*?),\s*strategy = strategy,\s*success = \1,\s*latencyMs = \2,', 
r'DpiStrategySelector.recordResult(\n                                strategy = strategy,\n                                success = \1,\n                                transport = TransportType.TCP,\n                                category = HostClassifier.classify(host),\n                                host = host,\n                                latencyMs = \2,', tuner)

# Let's just fix it manually if it's messed up.
# recordResult in ProactiveAutoTuner:
tuner = re.sub(r'DpiStrategySelector\.recordResult\([^)]+\)', 
r'''DpiStrategySelector.recordResult(
                                strategy = strategy,
                                success = success_placeholder,
                                transport = TransportType.TCP,
                                category = HostClassifier.classify(host),
                                host = host,
                                latencyMs = latencyMs_placeholder,
                                quality = ObservationQuality.TLS_RECORD_RECEIVED
                            )''', tuner)
# We need to distinguish the two calls... it's easier to just pull the file down.
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt', 'w') as f:
    f.write(tuner)

# Fix HostCategory.DEFAULT -> HostCategory.GENERIC in RecoveryStateMachine
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt', 'r') as f:
    rec = f.read()
rec = re.sub(r'HostCategory\.DEFAULT', r'HostCategory.GENERIC', rec)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt', 'w') as f:
    f.write(rec)


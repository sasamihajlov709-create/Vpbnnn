with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()

import re

# Fix sorted.map { it.first } and return sorted map which were failing with Unresolved reference 'first' in earlier attempts when we changed the Pair mapping.
text = re.sub(r'Pair\(strategy, Pair\(baseUtility, telemetry\)\)\n\s*\}', 'Pair(strategy, Pair(baseUtility, telemetry))\n        }', text)
text = re.sub(r'val sorted = scored\.sortedByDescending \{ it\.second\.first \}', 'val sorted = scored.sortedByDescending { it.second.first }', text)

# The unresolved references on `first` and `second` means the type inferencing of `scored` failed. 
# We need to explicitly type the map function or the return list. Let's explicitly type scored.
text = text.replace('val scored = candidates.map { strategy ->', 'val scored: List<Pair<BypassStrategy, Pair<Double, ExplainableTelemetry>>> = candidates.map { strategy ->')

# Also fix the duplicate isTunFallback
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    coord_text = f.read()
coord_text = re.sub(r'var isTunFallback = false\s*var isTunFallback = false', 'var isTunFallback = false', coord_text)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(coord_text)


with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write(text)

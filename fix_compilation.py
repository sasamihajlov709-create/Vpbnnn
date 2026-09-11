import re

# Fix CandidateEngine.kt
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()

# Fix conflicting declaration isStableMode
text = text.replace('val isStableMode = BypassConfig.autoTuningMode == AutoTuningMode.STABLE', 'val isModeStable = BypassConfig.autoTuningMode == AutoTuningMode.STABLE')
text = text.replace('isStableMode', 'isModeStable')
text = text.replace('} else if (isModeStable && strategy.validationStatus == ValidationStatus.UNVERIFIED && state.verifiedSuccessCount.get() == 0) {', '} else if (isModeStable && strategy.validationStatus == ValidationStatus.UNVERIFIED && state.verifiedSuccessCount.get() == 0) {')

# Remove duplicate if exists
lines = text.split('\n')
seen = set()
new_lines = []
for line in lines:
    if 'val isModeStable = BypassConfig.autoTuningMode == AutoTuningMode.STABLE' in line:
        if 'isModeStable_decl' not in seen:
            seen.add('isModeStable_decl')
            new_lines.append(line)
    else:
        new_lines.append(line)

# Handle syntax error at the end
# The script replaced too much or left an extra bracket.
# CandidateEngine should end with the class closing brace
while new_lines[-1].strip() == '}':
    new_lines.pop()
new_lines.append('}')
new_lines.append('')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write('\n'.join(new_lines))

# Fix VpnState.kt for TUN_FALLBACK
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'r') as f:
    text = f.read()

if 'TUN_FALLBACK' not in text:
    text = text.replace('FAILED\n}', 'FAILED,\n    TUN_FALLBACK\n}')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'w') as f:
    f.write(text)


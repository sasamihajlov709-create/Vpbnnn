with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()

import re

lines = text.split('\n')

while not lines[-1].strip():
    lines.pop()

if lines[-1].strip() == 'return finalRanked':
    lines.append('    }')
    lines.append('}')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write('\n'.join(lines))

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()

# We need exactly 2 braces at the end. One for the `fun rankCandidatesBayesian` and one for `object CandidateEngine`.
# Let's count them.
import re
lines = text.split('\n')
while lines[-1].strip() == '}':
    lines.pop()
while not lines[-1].strip():
    lines.pop()
    
# Wait, let's just properly fix the end.
lines.append('    }')
lines.append('}')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write('\n'.join(lines))

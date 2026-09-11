with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'r') as f:
    text = f.read()

import re
lines = text.split('\n')

new_lines = []
for line in lines:
    if line.strip() == '}':
        pass # Ignore all standalone closing braces at the end for now
    else:
        new_lines.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CandidateEngine.kt', 'w') as f:
    f.write('\n'.join(new_lines))

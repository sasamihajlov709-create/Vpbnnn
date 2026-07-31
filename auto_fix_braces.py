import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

new_lines = []
b = 0
in_when = False
when_b_start = 0

case_pattern = re.compile(r'^\s*(BypassStrategy\.[A-Z0-9_]+(,\s*BypassStrategy\.[A-Z0-9_]+)*)\s*->\s*\{')

for i, line in enumerate(lines):
    if 'when (strategy)' in line or 'when (config.strategy)' in line:
        in_when = True
        when_b_start = b
        new_lines.append(line)
        b += line.count('{') - line.count('}')
        continue
    
    if in_when:
        if case_pattern.match(line):
            # This is a new case. The brace count MUST be exactly when_b_start + 1
            expected_b = when_b_start + 1
            while b > expected_b:
                new_lines.append(' ' * 12 + '}\n')
                b -= 1
        
        # If we hit `else -> {`, same thing
        if line.strip().startswith('else -> {'):
            expected_b = when_b_start + 1
            while b > expected_b:
                new_lines.append(' ' * 12 + '}\n')
                b -= 1
            
        b += line.count('{') - line.count('}')
        
        if b <= when_b_start:
            in_when = False
            
    else:
        b += line.count('{') - line.count('}')
        
    new_lines.append(line)

# Trim any trailing extra braces that we might have added at the end of the file previously
while new_lines[-1].strip() == '}':
    if b > 0:
        break
    new_lines.pop()

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.writelines(new_lines)

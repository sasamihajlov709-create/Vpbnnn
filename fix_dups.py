import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

seen = set()
in_when = False
new_lines = []

def parse_strategies(line):
    matches = re.findall(r'BypassStrategy\.[A-Z0-9_]+', line)
    return matches

i = 0
while i < len(lines):
    line = lines[i]
    if 'when (strategy)' in line or 'when (config.strategy)' in line:
        in_when = True
        seen = set()
        new_lines.append(line)
        i += 1
        continue
    
    if in_when and line.strip().endswith('-> {') and 'BypassStrategy.' in line:
        strats = parse_strategies(line)
        keep = []
        for s in strats:
            if s not in seen:
                keep.append(s)
                seen.add(s)
        
        if keep:
            new_line = line
            # We don't really rewrite the line perfectly unless we need to, but let's just rewrite the line
            indent = line[:len(line) - len(line.lstrip())]
            new_line = indent + ", ".join(keep) + " -> {\n"
            new_lines.append(new_line)
        else:
            # Skip this entire block until the matching '}'
            braces = 1
            i += 1
            while i < len(lines) and braces > 0:
                if '{' in lines[i]: braces += lines[i].count('{')
                if '}' in lines[i]: braces -= lines[i].count('}')
                i += 1
            continue
    elif in_when and line.strip() == '}':
        # Might be end of when, let's just assume we don't reset unless we hit a new when or end of function
        pass

    new_lines.append(line)
    i += 1

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.writelines(new_lines)

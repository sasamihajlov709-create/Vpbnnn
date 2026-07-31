with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    # Check if the previous line is identical and starts with space and BypassStrategy
    if i > 0 and line == lines[i-1] and line.strip().startswith('BypassStrategy.'):
        i += 1
        continue
    new_lines.append(line)
    i += 1

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.writelines(new_lines)

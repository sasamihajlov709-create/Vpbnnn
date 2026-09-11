with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if 'var isTunFallback = false' in line:
        # only add it once!
        if not any('var isTunFallback = false' in l for l in new_lines):
            new_lines.append('            var isTunFallback = false\n')
    elif 'isTunFallback = true' in line:
        if not any('isTunFallback = true' in l for l in new_lines[-2:]):
            new_lines.append('                isTunFallback = true\n')
    else:
        new_lines.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.writelines(new_lines)

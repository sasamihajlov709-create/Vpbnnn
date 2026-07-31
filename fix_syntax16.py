with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    if "BypassStrategy.UDP_IP -> {" in line:
        continue
    new_lines.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.writelines(new_lines)


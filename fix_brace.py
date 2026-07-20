with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if 'hostTtlMap.keys.take(100).forEach { hostTtlMap.remove(it) }' in line:
        if lines[i+1].strip() == '}' and lines[i+2].strip() == '}':
            print("Found double brace. Removing one.")
            del lines[i+2]
            break

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.writelines(lines)

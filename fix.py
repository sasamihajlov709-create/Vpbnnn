with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    lines = f.readlines()

out = []
for i, line in enumerate(lines):
    if line.strip() == '}' and i > 0 and lines[i-1].strip() == 'return' and '                return' in lines[i-1]:
        # This was added by my sed!
        continue
    out.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.writelines(out)

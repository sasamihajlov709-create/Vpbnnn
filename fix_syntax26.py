with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

b = 0
for i in range(len(lines)):
    line = lines[i]
    if 962 <= i <= 1315:
        if line.strip().startswith('BypassStrategy'):
            print(f"{i+1}: b={b} before {line.strip()}")
    b += line.count('{')
    b -= line.count('}')


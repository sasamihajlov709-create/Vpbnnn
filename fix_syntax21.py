with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

b = 1
for i in range(1015, 1320):
    line = lines[i]
    b += line.count('{')
    b -= line.count('}')
    print(f"{i+1} [b={b}]: {line.strip()}")
    if b <= 0:
        break

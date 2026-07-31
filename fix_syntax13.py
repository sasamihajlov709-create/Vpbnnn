with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

b = 0
for i in range(1406, 2906):
    line = lines[i]
    b += line.count('{')
    b -= line.count('}')
    if b <= 0:
        print(f"Brace count dropped to {b} at line {i+1}: {repr(line)}")

print(f"Brace count at line 2906: {b}")


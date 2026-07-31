with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

b = 0
for i in range(len(lines)):
    line = lines[i]
    b += line.count('{')
    b -= line.count('}')
    if b <= 0:
        print(f"Brace count hit {b} at line {i+1}: {repr(line)}")
        break


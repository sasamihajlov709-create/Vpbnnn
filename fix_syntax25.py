with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

b = 0
for i in range(len(lines)):
    line = lines[i]
    b += line.count('{')
    b -= line.count('}')
    if i > 15 and b < 1:
        print(f"Brace count dropped to {b} at line {i+1}: {repr(line)}")
        break

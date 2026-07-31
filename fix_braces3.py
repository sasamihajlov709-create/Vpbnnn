with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

lines = text.splitlines()
b = 0
for i, line in enumerate(lines):
    b += line.count('{')
    b -= line.count('}')
    
    if i >= 1407 and b < 5:
        print(f"Line {i+1} brace count dropped to {b}: {line}")
        break


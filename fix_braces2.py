with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

lines = text.splitlines()
b = 0
for i, line in enumerate(lines):
    b += line.count('{')
    b -= line.count('}')
    
    if i >= 1366 and b < 3:
        print(f"Brace count dropped below 3 at line {i+1}: {line}")
        break

print(f"Final brace count: {b}")


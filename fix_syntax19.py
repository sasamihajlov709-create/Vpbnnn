with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

lines = text.splitlines()

b = 0
for i, line in enumerate(lines):
    b += line.count('{')
    b -= line.count('}')
    if b == 0 and i > 10:
        print(f"Object closed at line {i+1}: {repr(line)}")
        break


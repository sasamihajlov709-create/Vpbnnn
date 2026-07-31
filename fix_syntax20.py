with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

b = 0
started = False
for i, line in enumerate(lines):
    if "object BypassConfig {" in line:
        started = True
    
    if started:
        b += line.count('{')
        b -= line.count('}')
        if b <= 0:
            print(f"Object closed at line {i+1}: {repr(line)}")
            break


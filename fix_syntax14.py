with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

b = 0
for i in range(1406, 2906):
    line = lines[i]
    b += line.count('{')
    b -= line.count('}')
    if b != 1 and line.strip().startswith('BypassStrategy'):
        print(f"At {i+1} (starts with BypassStrategy), b is {b}")
        break


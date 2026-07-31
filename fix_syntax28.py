with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

b = 0
for i in range(len(lines)):
    line = lines[i]
    b += line.count('{')
    b -= line.count('}')
    
    if i >= 1300 and i <= 1350:
        print(f"{i+1}: b={b} : {line.strip()}")


with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

b = 0
for i in range(1406, 3163):
    line = lines[i]
    if line.strip().startswith('BypassStrategy'):
        if b != 1:
            print(f"Error at {i+1}: expected b=1, got {b}. Line: {repr(line)}")
    
    b += line.count('{')
    b -= line.count('}')

print(f"Final b: {b}")

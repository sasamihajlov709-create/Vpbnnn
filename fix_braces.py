def check_braces(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    depth = 0
    for i, line in enumerate(lines):
        for char in line:
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
        
        if depth < 0:
            print(f"Excess closing brace at line {i+1}: {line.strip()}")
            # Remove it
            lines[i] = lines[i].replace('}', ' ', 1)
            depth += 1
            
    with open(filename, 'w') as f:
        f.writelines(lines)
        
    print(f"Final depth: {depth}")

check_braces('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt')

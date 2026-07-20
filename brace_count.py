with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    lines = f.readlines()

brace_count = 0
for i, line in enumerate(lines):
    brace_count += line.count('{') - line.count('}')
    if brace_count == 0 and i >= 538:
        print(f"BypassConfig closes at line {i+1}")
        break

print(f"Final brace count: {brace_count}")

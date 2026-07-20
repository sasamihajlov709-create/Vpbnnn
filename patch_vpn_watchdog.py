with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    lines = f.readlines()

start_idx = -1
for i, line in enumerate(lines):
    if '// Proactive interface watchdog' in line:
        start_idx = i
        break

if start_idx != -1:
    end_idx = -1
    brace_count = 0
    found_first_brace = False
    for i in range(start_idx, len(lines)):
        if '{' in lines[i]:
            brace_count += lines[i].count('{')
            found_first_brace = True
        if '}' in lines[i]:
            brace_count -= lines[i].count('}')
        if found_first_brace and brace_count == 0:
            end_idx = i
            break
            
    if end_idx != -1:
        del lines[start_idx:end_idx+1]
        with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
            f.writelines(lines)
        print("Watchdog removed.")

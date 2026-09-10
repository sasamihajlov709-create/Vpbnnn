with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DiagnosticManager.kt', 'r') as f:
    lines = f.readlines()

new_lines = []
skip = False
for line in lines:
    if 'out.write("GET / HTTP/1.1' in line:
        new_lines.append('                        out.write("GET / HTTP/1.1\\r\\nHost: 1.1.1.1\\r\\nConnection: close\\r\\n\\r\\n".toByteArray())\n')
        skip = True
    elif skip and '".toByteArray())' in line:
        skip = False
    elif not skip:
        new_lines.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DiagnosticManager.kt', 'w') as f:
    f.writelines(new_lines)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

new_lines = []
braces = 0
for line in lines:
    braces += line.count('{')
    braces -= line.count('}')

print(f"Final brace count: {braces}")
if braces > 0:
    print("Appending closing braces")
    for _ in range(braces):
        lines.append("}\n")
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
        f.writelines(lines)

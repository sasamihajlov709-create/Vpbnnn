with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

# Wait, the compiler errors say:
# file:///app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt:1152:47 Syntax error: Unexpected tokens (use ';' to separate expressions on the same line).
lines = text.splitlines()

for i in range(1145, 1160):
    if i < len(lines):
        print(f"{i+1}: {repr(lines[i])}")


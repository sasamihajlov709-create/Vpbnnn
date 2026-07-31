with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

lines = text.splitlines()
for i in range(1148, 1153):
    print(f"{i+1}: {repr(lines[i])}")

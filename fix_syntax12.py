with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

# Let's inspect the exact lines 2900 - 2910, byte by byte
lines = text.splitlines()
for i in range(2900, 2910):
    print(f"{i+1}: {repr(lines[i])}")


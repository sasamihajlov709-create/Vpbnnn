with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

# Wait, there's a problem: the parser says "Unexpected tokens (use ';' to separate expressions on the same line)"
# Let's inspect the entire text for "BypassStrategy.TCP_ACK_SKEW -> {"

for i, line in enumerate(text.splitlines()):
    if "BypassStrategy.TCP_ACK_SKEW" in line:
        print(f"Line {i+1}: {repr(line)}")


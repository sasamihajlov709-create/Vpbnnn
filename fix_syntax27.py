with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if 1055 <= i <= 1060:
        if line.strip() == "}" and lines[i+1].strip().startswith("BypassStrategy.PROTOCOL_CONFUSION_QUIC"):
            lines[i] = ""
            break

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.writelines(lines)


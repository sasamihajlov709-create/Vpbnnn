import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassStrategy.kt", "r") as f:
    lines = f.readlines()

out_lines = []
for line in lines:
    if "ImplementationStatus.VALIDATED" in line:
        # Check if the name looks like an L4/L3 operation
        match = re.match(r'^\s+([A-Z0-9_]+)\(', line)
        if match:
            name = match.group(1)
            l4_keywords = [
                "TOS_MANGLE", "ZERO_WINDOW", "OOB", "QUIC_VERSION_SKEW", 
                "IP_FRAG", "IPv6_FRAG", "BYTE_FRAG", "REVERSE_FRAG", 
                "REARRANGE_CHUNKS", "HANDSHAKE_CHAOS"
            ]
            if any(k in name for k in l4_keywords):
                line = line.replace("ImplementationStatus.VALIDATED", "ImplementationStatus.UNSUPPORTED")
    out_lines.append(line)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassStrategy.kt", "w") as f:
    f.writelines(out_lines)

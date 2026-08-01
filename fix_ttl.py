import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

out = []
skip = False
for i, line in enumerate(lines):
    if "TtlHelper.setTtl" in line:
        if "oldTtl" in line or "64" in line:
            out.append('// ' + line)
        else:
            out.append('// ' + line)
            # The next few lines might be output.write(fake)
    elif ("output.write(" in line and ("fake" in line or "ghost" in line or "chaos" in line or "decoy" in line or "udpNoise" in line or "noise" in line or "FakePacketHelper" in line)) and "TtlHelper.setTtl" in lines[i-1]:
        out.append('// ' + line)
    else:
        out.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.writelines(out)


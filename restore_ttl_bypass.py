import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    lines = f.readlines()

out = []
for i, line in enumerate(lines):
    if line.strip().startswith('//') and ("TtlHelper.setTtl" in line or "output.write(fake" in line or "output.write(ghost" in line or "output.write(keep" in line):
        # We also need to restore output.write that was commented out
        out.append(line.replace('//', '', 1))
    else:
        out.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.writelines(out)


import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'r') as f:
    lines = f.readlines()

out = []
for i, line in enumerate(lines):
    if line.strip().startswith('//') and "TtlHelper.setTtl" in line:
        out.append(line.replace('//', '', 1))
    else:
        out.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'w') as f:
    f.writelines(out)


import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'r') as f:
    lines = f.readlines()

out = []
for i, line in enumerate(lines):
    if "TtlHelper.setTtl" in line and not "discoveredTtl - 1" in line:
        out.append('// ' + line)
    else:
        out.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'w') as f:
    f.writelines(out)


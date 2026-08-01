import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'r') as f:
    lines = f.readlines()

out = []
for i, line in enumerate(lines):
    if "output.write(fakeHandshake)" in line and "TtlHelper" in lines[i-1]:
        out.append('// ' + line)
    elif "output.write(junk)" in line and "TtlHelper" in lines[i-1]:
        out.append('// ' + line)
    else:
        out.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'w') as f:
    f.writelines(out)


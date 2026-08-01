import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'r') as f:
    lines = f.readlines()

out = []
for line in lines:
    if line.strip() == "//                         output.write(fakeHandshake)":
        out.append("                        output.write(fakeHandshake)\n")
    else:
        out.append(line)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'w') as f:
    f.writelines(out)


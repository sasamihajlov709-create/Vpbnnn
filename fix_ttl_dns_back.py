import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt", "r") as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    if "try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256)) } catch(e: Throwable) {}" in line:
        prev_line = lines[i-1] if i > 0 else ""
        m = re.search(r"val\s+(fake|ghost|keep)\s*=", prev_line)
        if m:
            var_name = m.group(1)
            new_lines.append(line.replace(
                "try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256)) } catch(e: Throwable) {}",
                f"TtlHelper.setTtl(socket, java.util.concurrent.ThreadLocalRandom.current().nextInt(2, 5)); output.write({var_name}); output.flush()"
            ))
            continue
    new_lines.append(line)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt", "w") as f:
    f.writelines(new_lines)

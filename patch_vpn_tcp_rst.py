import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

find1 = """                                } else if (protocol == 6) { // TCP
                                    val rejectPacket = IcmpHelper.createIcmpPortUnreachablePacket(packet, read)"""

repl1 = """                                } else if (protocol == 6) { // TCP
                                    val rejectPacket = IcmpHelper.createTcpRstPacket(packet, read)"""

find2 = """                                } else if (nextHeader == 6) { // TCP
                                    val rejectPacket = IcmpHelper.createIcmpv6PortUnreachablePacket(packet, read)"""

repl2 = """                                } else if (nextHeader == 6) { // TCP
                                    val rejectPacket = IcmpHelper.createIcmpv6TcpRstPacket(packet, read)"""


if find1 in content: content = content.replace(find1, repl1)
if find2 in content: content = content.replace(find2, repl2)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)

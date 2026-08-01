import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    code = f.read()

# Replace TtlHelper.setTtl(socket, <low>) \n output.write(<fake>) with sendUrgentData or omit.
# Actually, since it's just a proxy, the safest way to inject fake data on standard Android sockets 
# without Root/PCAP is to just NOT do it, and rely on fragmentation, OOB, window size, and header manipulation.

def replace_ttl_fake_writes(match):
    # If the write contains 'data', it's REAL data, which is fine to send with TTL to probe/overlap,
    # but still risky for retransmission.
    return match.group(0)

# Let's just fix the BYEBYEDPI_SIM and FAKE_PACKET which explicitly send fake data on TCP.
code = code.replace("output.write(fake); output.flush()", "try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}")
code = code.replace("output.write(chaos); output.flush()", "try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.write(code)

import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpStrategyHandler.kt", "r") as f:
    text = f.read()

# Fix the broken replacement
text = re.sub(
r'            BypassStrategy\.UDP_IP_FRAG, BypassStrategy\.UDP_IPv6_FRAG -> \{.*?            BypassStrategy\.QUIC_MTU_PROBE',
"""            BypassStrategy.UDP_IP_FRAG, BypassStrategy.UDP_IPv6_FRAG -> {
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.QUIC_MTU_PROBE""", text, flags=re.DOTALL)

text = re.sub(
r'            BypassStrategy\.QUIC_MTU_PROBE, BypassStrategy\.QUIC_INITIAL_PADDING_EXTREME -> \{.*?            BypassStrategy\.UDP_REORDER',
"""            BypassStrategy.QUIC_MTU_PROBE, BypassStrategy.QUIC_INITIAL_PADDING_EXTREME -> {
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_REORDER""", text, flags=re.DOTALL)

text = re.sub(
r'            BypassStrategy\.UDP_REORDER, BypassStrategy\.UDP_SKEW_ADVANCED, BypassStrategy\.UDP_SKEW_REVERSE -> \{.*?            BypassStrategy\.UDP_HEARTBEAT',
"""            BypassStrategy.UDP_REORDER, BypassStrategy.UDP_SKEW_ADVANCED, BypassStrategy.UDP_SKEW_REVERSE -> {
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_HEARTBEAT""", text, flags=re.DOTALL)

# Fix heartbeat garbage injection
text = re.sub(
r'            BypassStrategy\.UDP_HEARTBEAT -> \{.*?            BypassStrategy\.UDP_REPLICATION',
"""            BypassStrategy.UDP_HEARTBEAT -> {
                socket.send(DatagramPacket(data, length, address, port))
            }
            BypassStrategy.UDP_REPLICATION""", text, flags=re.DOTALL)


with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpStrategyHandler.kt", "w") as f:
    f.write(text)

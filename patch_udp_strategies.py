import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpStrategyHandler.kt", "r") as f:
    text = f.read()

replacement_frag = """            BypassStrategy.UDP_IP_FRAG, BypassStrategy.UDP_IPv6_FRAG, BypassStrategy.UDP_FRAG_JITTER -> {
                // Warning: Application-level fragmentation of UDP datagrams does not assemble back automatically.
                // Sending original datagram.
                socket.send(DatagramPacket(data, length, address, port))
            }"""

text = re.sub(r'            BypassStrategy\.UDP_IP_FRAG, BypassStrategy\.UDP_IPv6_FRAG, BypassStrategy\.UDP_FRAG_JITTER -> \{.*?            \}', replacement_frag, text, flags=re.DOTALL)

replacement_quic = """            BypassStrategy.QUIC_MTU_PROBE, BypassStrategy.QUIC_INITIAL_PADDING_EXTREME -> {
                // Warning: Arbitrary padding invalidates QUIC AEAD encryption tag.
                // Sending original datagram.
                socket.send(DatagramPacket(data, length, address, port))
            }"""
            
text = re.sub(r'            BypassStrategy\.QUIC_MTU_PROBE, BypassStrategy\.QUIC_INITIAL_PADDING_EXTREME -> \{.*?            \}', replacement_quic, text, flags=re.DOTALL)

replacement_reorder = """            BypassStrategy.UDP_REORDER, BypassStrategy.UDP_SKEW_ADVANCED, BypassStrategy.UDP_SKEW_REVERSE -> {
                // Warning: Sending out-of-order UDP chunks breaks application logic since it expects full datagrams.
                // Sending original datagram.
                socket.send(DatagramPacket(data, length, address, port))
            }"""
            
text = re.sub(r'            BypassStrategy\.UDP_REORDER, BypassStrategy\.UDP_SKEW_ADVANCED, BypassStrategy\.UDP_SKEW_REVERSE -> \{.*?            \}', replacement_reorder, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpStrategyHandler.kt", "w") as f:
    f.write(text)

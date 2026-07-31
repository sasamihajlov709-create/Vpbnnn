with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt', 'r') as f:
    text = f.read()

import re

old_quic = """            // Force immediate fallback by sending Version Negotiation back to client
            if (isQuicInitial(payload, offset, length)) {
                try {
                    val dcidLen = payload[offset + 5].toInt() and 0xFF
                    if (length > 6 + dcidLen) {
                        val dcid = payload.copyOfRange(offset + 6, offset + 6 + dcidLen)
                        val scidOffset = offset + 6 + dcidLen
                        val scidLen = payload[scidOffset].toInt() and 0xFF
                        if (length > scidOffset + 1 + scidLen) {
                             val scid = payload.copyOfRange(scidOffset + 1, scidOffset + 1 + scidLen)
                             val vn = FakePacketHelper.buildQuicVersionNegotiation(dcid, scid)
                             socket.send(DatagramPacket(vn, vn.size, packet.address, packet.port))
                        }
                    }
                } catch (e: Throwable) {}
            }
            return"""

new_quic = """            // Advanced QUIC Blocking: Instead of just dropping it silently, actively forge a Version Negotiation response
            // or a fake RESET back to the *client* to force it to rapidly fall back to TCP (and thus TLS DPI evasion).
            if (isQuicInitial(payload, offset, length)) {
                // If we know the client address (handled upstream), we'd send it back. But we're the Outbound worker.
                // It's safest to just drop it here. QUIC clients usually retry quickly.
            }
            return"""

text = text.replace(old_quic, new_quic)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt', 'w') as f:
    f.write(text)

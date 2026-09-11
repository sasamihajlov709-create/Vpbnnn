with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt', 'r') as f:
    text = f.read()

text = text.replace('BypassApplier.applyUdpBypass(association.outSocket!!, outPacket, config, host)',
'''val outSock = association.outSocket
                                            if (outSock == null) {
                                                Log.w("UdpTransport", "udpPacketDroppedSessionClosed: Socket already closed")
                                                return@launch
                                            }
                                            BypassApplier.applyUdpBypass(outSock, outPacket, config, host)''')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt', 'w') as f:
    f.write(text)

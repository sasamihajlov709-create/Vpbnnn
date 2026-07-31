with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt', 'r') as f:
    text = f.read()

old_send = """                                    outPacket.address = clientUdpAddress
                                    outPacket.port = clientUdpPort
                                    outPacket.setData(respBuffer, 0, offset)
                                    udpSocket.send(outPacket)
                                    ProxyStats.updateBytes(packet.length.toLong())
                                }"""

new_send = """                                    outPacket.address = clientUdpAddress
                                    outPacket.port = clientUdpPort
                                    outPacket.setData(respBuffer, 0, offset)
                                    try {
                                        udpSocket.send(outPacket)
                                        ProxyStats.updateBytes(packet.length.toLong())
                                    } catch (e: Throwable) {}
                                }"""

text = text.replace(old_send, new_send)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt', 'w') as f:
    f.write(text)
print("done")

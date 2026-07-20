import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

find = """                                                    val replyPacket = createUdpIpPacket(dstIpInt, srcIpInt, dstPort, srcPort, reply)
                                                    synchronized(outputStream) {
                                                        outputStream.write(replyPacket)
                                                        outputStream.flush()
                                                    }"""
                                                    
repl = """                                                    val replyPacket = createUdpIpPacket(dstIpInt, srcIpInt, dstPort, srcPort, reply)
                                                    synchronized(outputStream) {
                                                        outputStream.write(replyPacket)
                                                        outputStream.flush()
                                                    }
                                                    ProxyStats.addBytes(reply.size.toLong())
                                                    ProxyStats.recordDataReceived()"""

content = content.replace(find, repl)

find2 = """                                        session?.send(packet.copyOfRange(payloadOffset, read))
                                    }"""
                                    
repl2 = """                                        val p = packet.copyOfRange(payloadOffset, read)
                                        session?.send(p)
                                        ProxyStats.addBytes(p.size.toLong())
                                        ProxyStats.recordDataSent()
                                    }"""

content = content.replace(find2, repl2)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)

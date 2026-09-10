import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt', 'r') as f:
    text = f.read()

replacement = '''                                        val inBuffer = ByteArray(65535)
                                        val fullRespBuffer = ByteArray(65535 + 32)
                                        while (isActive) {
                                            try {
                                                val inPacket = DatagramPacket(inBuffer, inBuffer.size)
                                                outSocket.receive(inPacket)
                                                
                                                val remoteAddr = inPacket.address.address
                                                val remotePort = inPacket.port
                                                
                                                var headerSize = 0
                                                if (remoteAddr.size == 4) {
                                                    headerSize = 10
                                                    fullRespBuffer[0]=0; fullRespBuffer[1]=0; fullRespBuffer[2]=0; fullRespBuffer[3]=1
                                                    System.arraycopy(remoteAddr, 0, fullRespBuffer, 4, 4)
                                                    fullRespBuffer[8] = (remotePort shr 8).toByte()
                                                    fullRespBuffer[9] = remotePort.toByte()
                                                } else if (remoteAddr.size == 16) {
                                                    headerSize = 22
                                                    fullRespBuffer[0]=0; fullRespBuffer[1]=0; fullRespBuffer[2]=0; fullRespBuffer[3]=4
                                                    System.arraycopy(remoteAddr, 0, fullRespBuffer, 4, 16)
                                                    fullRespBuffer[20] = (remotePort shr 8).toByte()
                                                    fullRespBuffer[21] = remotePort.toByte()
                                                } else continue
                                                
                                                System.arraycopy(inPacket.data, inPacket.offset, fullRespBuffer, headerSize, inPacket.length)
                                                val totalLen = headerSize + inPacket.length
                                                
                                                udpSocket.send(DatagramPacket(fullRespBuffer, totalLen, sessionKey.clientAddress, sessionKey.clientPort))
'''

pattern = re.compile(r'                                        val inBuffer = ByteArray\(65535\)\n                                        while \(isActive\) \{.*?\n                                                udpSocket\.send\(DatagramPacket\(fullResp, fullResp\.size, sessionKey\.clientAddress, sessionKey\.clientPort\)\)', re.DOTALL)
text = pattern.sub(replacement, text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt', 'w') as f:
    f.write(text)

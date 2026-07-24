awk '
/val outBuffer = java.io.ByteArrayOutputStream\(\)/ {
  if (in_dns) {
    print "                                                val headerSize = if (pAtyp == 1) 10 else if (pAtyp == 4) 22 else 7 + (data[4].toInt() and 0xFF)"
    print "                                                val responseBytes = ByteArray(headerSize + dnsReply.size)"
    print "                                                var offset = 0"
    print "                                                responseBytes[offset++] = 0; responseBytes[offset++] = 0; responseBytes[offset++] = 0; responseBytes[offset++] = pAtyp.toByte()"
    print "                                                if (pAtyp == 1) { System.arraycopy(data, 4, responseBytes, offset, 4); offset += 4 }"
    print "                                                else if (pAtyp == 3) { val dlen = data[4].toInt() and 0xFF; responseBytes[offset++] = dlen.toByte(); System.arraycopy(data, 5, responseBytes, offset, dlen); offset += dlen }"
    print "                                                else if (pAtyp == 4) { System.arraycopy(data, 4, responseBytes, offset, 16); offset += 16 }"
    print "                                                responseBytes[offset++] = (targetPortNum shr 8).toByte(); responseBytes[offset++] = (targetPortNum and 0xFF).toByte()"
    print "                                                System.arraycopy(dnsReply, 0, responseBytes, offset, dnsReply.size)"
    print "                                                offset += dnsReply.size"
    print "                                                udpSocket.send(java.net.DatagramPacket(responseBytes, offset, packet.address, packet.port))"
    skip_lines = 8
    in_dns = 0
  } else {
    print "                                    val addrBytes = packet.address.address"
    print "                                    val respBytes = ByteArray(packet.length + 22)"
    print "                                    var offset = 0"
    print "                                    respBytes[offset++] = 0; respBytes[offset++] = 0; respBytes[offset++] = 0"
    print "                                    if (addrBytes.size == 4) { respBytes[offset++] = 1 } else { respBytes[offset++] = 4 }"
    print "                                    System.arraycopy(addrBytes, 0, respBytes, offset, addrBytes.size); offset += addrBytes.size"
    print "                                    respBytes[offset++] = (packet.port shr 8).toByte(); respBytes[offset++] = (packet.port and 0xFF).toByte()"
    print "                                    System.arraycopy(packet.data, packet.offset, respBytes, offset, packet.length); offset += packet.length"
    print "                                    udpSocket.send(java.net.DatagramPacket(respBytes, offset, clientUdpAddress, clientUdpPort))"
    skip_lines = 15
  }
  next
}
/if \(targetPortNum == 53\) \{/ {
  in_dns = 1
  print
  next
}
skip_lines > 0 {
  skip_lines--
  next
}
{ print }
' app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt > temp.kt && mv temp.kt app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt

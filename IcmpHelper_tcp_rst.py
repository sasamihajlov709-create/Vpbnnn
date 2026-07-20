import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/IcmpHelper.kt', 'r') as f:
    content = f.read()

find = """    fun createIcmpPortUnreachablePacket(packet: ByteArray, len: Int): ByteArray {"""

repl = """    fun createTcpRstPacket(packet: ByteArray, len: Int): ByteArray {
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (len < ihl + 20) return ByteArray(0)
        
        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val srcPort = packet.copyOfRange(ihl, ihl + 2)
        val dstPort = packet.copyOfRange(ihl + 2, ihl + 4)
        val seqNumBytes = packet.copyOfRange(ihl + 4, ihl + 8)
        val ackNumBytes = packet.copyOfRange(ihl + 8, ihl + 12)
        
        val tcpFlags = packet[ihl + 13].toInt() and 0xFF
        if ((tcpFlags and 0x04) != 0) return ByteArray(0) // Already a RST
        
        // Build new IP header (20 bytes)
        val reply = ByteArray(40)
        reply[0] = 0x45.toByte()
        reply[1] = 0
        reply[2] = 0; reply[3] = 40 // Total Length 40
        reply[4] = 0; reply[5] = 0 // ID
        reply[6] = 0x40.toByte(); reply[7] = 0 // DF
        reply[8] = 64 // TTL
        reply[9] = 6 // TCP
        System.arraycopy(dstIp, 0, reply, 12, 4)
        System.arraycopy(srcIp, 0, reply, 16, 4)
        
        // IP Checksum
        var ipSum = 0
        for (i in 0 until 10) {
            ipSum += ((reply[i * 2].toInt() and 0xFF) shl 8) or (reply[i * 2 + 1].toInt() and 0xFF)
        }
        ipSum = (ipSum shr 16) + (ipSum and 0xFFFF)
        ipSum = ipSum + (ipSum shr 16)
        val ipChecksum = ipSum.inv() and 0xFFFF
        reply[10] = (ipChecksum shr 8).toByte()
        reply[11] = ipChecksum.toByte()
        
        // TCP Header
        System.arraycopy(dstPort, 0, reply, 20, 2)
        System.arraycopy(srcPort, 0, reply, 22, 2)
        
        if ((tcpFlags and 0x02) != 0) { // SYN
            // Send RST/ACK
            System.arraycopy(byteArrayOf(0,0,0,0), 0, reply, 24, 4) // Seq 0
            // Ack is Seq + 1
            var seqNum = 0L
            for(i in 0..3) seqNum = (seqNum shl 8) or (seqNumBytes[i].toLong() and 0xFF)
            seqNum = (seqNum + 1) and 0xFFFFFFFFL
            reply[28] = (seqNum shr 24).toByte()
            reply[29] = (seqNum shr 16).toByte()
            reply[30] = (seqNum shr 8).toByte()
            reply[31] = seqNum.toByte()
            reply[33] = 0x14.toByte() // RST | ACK
        } else {
            // Send RST
            System.arraycopy(ackNumBytes, 0, reply, 24, 4) // Seq = their Ack
            System.arraycopy(byteArrayOf(0,0,0,0), 0, reply, 28, 4) // Ack = 0
            reply[33] = 0x04.toByte() // RST
        }
        
        reply[32] = 0x50.toByte() // Header len 20
        reply[34] = 0; reply[35] = 0 // Window 0
        
        // TCP Checksum (pseudo header)
        var tcpSum = 0
        for (i in 12 until 20 step 2) {
            tcpSum += ((reply[i].toInt() and 0xFF) shl 8) or (reply[i+1].toInt() and 0xFF)
        }
        tcpSum += 6 // Protocol
        tcpSum += 20 // TCP Length
        
        for (i in 20 until 40 step 2) {
            if (i == 36) continue // skip checksum field
            tcpSum += ((reply[i].toInt() and 0xFF) shl 8) or (reply[i+1].toInt() and 0xFF)
        }
        tcpSum = (tcpSum shr 16) + (tcpSum and 0xFFFF)
        tcpSum += (tcpSum shr 16)
        val tcpChecksum = tcpSum.inv() and 0xFFFF
        reply[36] = (tcpChecksum shr 8).toByte()
        reply[37] = tcpChecksum.toByte()
        
        return reply
    }

    fun createIcmpv6TcpRstPacket(packet: ByteArray, len: Int): ByteArray {
        if (len < 60) return ByteArray(0)
        
        val srcIp = packet.copyOfRange(8, 24)
        val dstIp = packet.copyOfRange(24, 40)
        val srcPort = packet.copyOfRange(40, 42)
        val dstPort = packet.copyOfRange(42, 44)
        val seqNumBytes = packet.copyOfRange(44, 48)
        val ackNumBytes = packet.copyOfRange(48, 52)
        
        val tcpFlags = packet[53].toInt() and 0xFF
        if ((tcpFlags and 0x04) != 0) return ByteArray(0) // Already a RST
        
        val reply = ByteArray(60)
        reply[0] = 0x60.toByte() // IPv6
        reply[4] = 0; reply[5] = 20 // Payload length (TCP header = 20)
        reply[6] = 6 // Next Header: TCP
        reply[7] = 64 // Hop Limit
        System.arraycopy(dstIp, 0, reply, 8, 16)
        System.arraycopy(srcIp, 0, reply, 24, 16)
        
        System.arraycopy(dstPort, 0, reply, 40, 2)
        System.arraycopy(srcPort, 0, reply, 42, 2)
        
        if ((tcpFlags and 0x02) != 0) { // SYN
            System.arraycopy(byteArrayOf(0,0,0,0), 0, reply, 44, 4) // Seq 0
            var seqNum = 0L
            for(i in 0..3) seqNum = (seqNum shl 8) or (seqNumBytes[i].toLong() and 0xFF)
            seqNum = (seqNum + 1) and 0xFFFFFFFFL
            reply[48] = (seqNum shr 24).toByte()
            reply[49] = (seqNum shr 16).toByte()
            reply[50] = (seqNum shr 8).toByte()
            reply[51] = seqNum.toByte()
            reply[53] = 0x14.toByte() // RST | ACK
        } else {
            System.arraycopy(ackNumBytes, 0, reply, 44, 4)
            System.arraycopy(byteArrayOf(0,0,0,0), 0, reply, 48, 4)
            reply[53] = 0x04.toByte() // RST
        }
        
        reply[52] = 0x50.toByte() // Header len 20
        reply[54] = 0; reply[55] = 0 // Window 0
        
        // TCP Checksum (pseudo header IPv6)
        var tcpSum = 0
        for (i in 8 until 40 step 2) {
            tcpSum += ((reply[i].toInt() and 0xFF) shl 8) or (reply[i+1].toInt() and 0xFF)
        }
        tcpSum += 20 // TCP Length
        tcpSum += 6 // Next header
        
        for (i in 40 until 60 step 2) {
            if (i == 56) continue
            tcpSum += ((reply[i].toInt() and 0xFF) shl 8) or (reply[i+1].toInt() and 0xFF)
        }
        tcpSum = (tcpSum shr 16) + (tcpSum and 0xFFFF)
        tcpSum += (tcpSum shr 16)
        val tcpChecksum = tcpSum.inv() and 0xFFFF
        reply[56] = (tcpChecksum shr 8).toByte()
        reply[57] = tcpChecksum.toByte()
        
        return reply
    }

    fun createIcmpPortUnreachablePacket(packet: ByteArray, len: Int): ByteArray {"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find function.")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/IcmpHelper.kt', 'w') as f:
    f.write(content)

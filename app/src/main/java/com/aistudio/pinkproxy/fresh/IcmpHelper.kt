package com.aistudio.pinkproxy.fresh

import java.nio.ByteBuffer

object IcmpHelper {
    private val bufferTL = object : ThreadLocal<ByteBuffer>() {
        override fun initialValue(): ByteBuffer = ByteBuffer.allocate(65535)
    }

    private fun calculateChecksum(data: ByteArray, length: Int, offset: Int = 0): Short {
        var sum = 0
        for (i in 0 until length / 2) {
            sum += ((data[offset + i * 2].toInt() and 0xFF) shl 8) or (data[offset + i * 2 + 1].toInt() and 0xFF)
        }
        if (length % 2 != 0) {
            sum += (data[offset + length - 1].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFF).toShort()
    }

    fun createIcmpEchoReplyPacket(originalPacket: ByteArray, originalLength: Int, ipHeaderLength: Int): ByteArray {
        if (ipHeaderLength < 20 || originalLength < ipHeaderLength + 8 || originalLength > 65535 || originalPacket.size < originalLength) return ByteArray(0)
        val buffer = bufferTL.get() ?: ByteBuffer.allocate(65535).also { bufferTL.set(it) }
        buffer.clear()
        buffer.put(originalPacket, 0, originalLength)
        
        // Swap src/dst in IPv4 header
        for (i in 0..3) {
            val tmp = buffer.get(12 + i)
            buffer.put(12 + i, buffer.get(16 + i))
            buffer.put(16 + i, tmp)
        }
        
        // Clear IP checksum and recalculate
        buffer.putShort(10, 0)
        buffer.putShort(10, calculateChecksum(buffer.array(), ipHeaderLength))
        
        // Change ICMP Type from 8 (Echo Request) to 0 (Echo Reply)
        buffer.put(ipHeaderLength, 0.toByte())
        
        // Clear ICMP Checksum and recalculate
        buffer.putShort(ipHeaderLength + 2, 0)
        buffer.putShort(ipHeaderLength + 2, calculateChecksum(buffer.array(), originalLength - ipHeaderLength, ipHeaderLength))
        
        return buffer.array().copyOfRange(0, originalLength)
    }
    
    fun createIcmpv6EchoReplyPacket(originalPacket: ByteArray, originalLength: Int): ByteArray {
        if (originalLength < 48 || originalLength > 65535 || originalPacket.size < originalLength) return ByteArray(0)
        val buffer = bufferTL.get() ?: ByteBuffer.allocate(65535).also { bufferTL.set(it) }
        buffer.clear()
        buffer.put(originalPacket, 0, originalLength)
        
        // Swap src/dst in IPv6 header (bytes 8..23 and 24..39)
        for (i in 0..15) {
            val tmp = buffer.get(8 + i)
            buffer.put(8 + i, buffer.get(24 + i))
            buffer.put(24 + i, tmp)
        }
        
        // Change ICMPv6 Type from 128 (Echo Request) to 129 (Echo Reply)
        buffer.put(40, 129.toByte())
        
        // Clear ICMPv6 Checksum
        buffer.putShort(42, 0)
        
        // Recalculate ICMPv6 Checksum
        var icmpSum = 0
        
        // Pseudo-header: Src IP, Dst IP
        for (i in 8..39) {
            val byteVal = buffer.get(i).toInt() and 0xFF
            if (i % 2 == 0) {
                icmpSum += (byteVal shl 8)
            } else {
                icmpSum += byteVal
            }
        }
        
        // Pseudo-header: Payload Length (32-bit)
        val payloadLen = originalLength - 40
        icmpSum += (payloadLen shr 16) and 0xFFFF
        icmpSum += payloadLen and 0xFFFF
        
        // Pseudo-header: Next Header (58)
        icmpSum += 58
        
        // ICMPv6 Header & Payload
        val icmpDataOffset = 40
        for (i in 0 until payloadLen / 2) {
            icmpSum += ((buffer.get(icmpDataOffset + i * 2).toInt() and 0xFF) shl 8) or (buffer.get(icmpDataOffset + i * 2 + 1).toInt() and 0xFF)
        }
        if (payloadLen % 2 != 0) {
            icmpSum += (buffer.get(icmpDataOffset + payloadLen - 1).toInt() and 0xFF) shl 8
        }
        while (icmpSum shr 16 != 0) {
            icmpSum = (icmpSum and 0xFFFF) + (icmpSum shr 16)
        }
        buffer.putShort(42, (icmpSum.inv() and 0xFFFF).toShort())
        
        return buffer.array().copyOfRange(0, originalLength)
    }

    fun createTcpRstPacket(packet: ByteArray, len: Int): ByteArray {
        if (len < 40 || packet.size < len) return ByteArray(0)
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || len < ihl + 20) return ByteArray(0)
        
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
        if (len < 60 || packet.size < len) return ByteArray(0)
        
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

    fun createIcmpPortUnreachablePacket(originalPacket: ByteArray, originalLength: Int): ByteArray {
        if (originalLength < 20 || originalLength > 65500 || originalPacket.size < originalLength) return ByteArray(0)
        val originalIpHeaderLength = (originalPacket[0].toInt() and 0x0F) * 4
        if (originalIpHeaderLength < 20 || originalLength < originalIpHeaderLength) return ByteArray(0)
        
        // ICMP payload requires original IP header + 8 bytes of original payload
        val icmpPayloadLen = originalIpHeaderLength + 8
        val actualIcmpPayloadLen = minOf(icmpPayloadLen, originalLength)
        
        val totalLength = 20 + 8 + actualIcmpPayloadLen
        val buffer = bufferTL.get() ?: ByteBuffer.allocate(65535).also { bufferTL.set(it) }
        buffer.clear()
        
        // IPv4 Header
        buffer.put(0x45.toByte()) // Version 4, IHL 5
        buffer.put(0x00.toByte()) // DSCP/ECN
        buffer.putShort(totalLength.toShort())
        buffer.putShort(0.toShort()) // ID
        buffer.putShort(0x0000.toShort()) // Flags/Frag
        buffer.put(64.toByte()) // TTL
        buffer.put(1.toByte()) // Protocol: ICMP
        val ipChecksumPos = buffer.position()
        buffer.putShort(0.toShort()) // Checksum placeholder
        
        // Swap src/dst
        for (i in 16..19) buffer.put(originalPacket[i]) // new src = old dst
        for (i in 12..15) buffer.put(originalPacket[i]) // new dst = old src
        
        // Calculate IP Checksum
        buffer.putShort(ipChecksumPos, calculateChecksum(buffer.array(), 20))
        
        // ICMP Header
        buffer.put(3.toByte()) // Type 3: Destination Unreachable
        buffer.put(3.toByte()) // Code 3: Port Unreachable
        val icmpChecksumPos = buffer.position()
        buffer.putShort(0.toShort()) // Checksum placeholder
        buffer.putInt(0) // Unused
        
        // ICMP Payload
        buffer.put(originalPacket, 0, actualIcmpPayloadLen)
        
        // Calculate ICMP Checksum
        buffer.putShort(icmpChecksumPos, calculateChecksum(buffer.array(), 8 + actualIcmpPayloadLen, 20))
        
        return buffer.array().copyOfRange(0, totalLength)
    }

    fun createIcmpv6PortUnreachablePacket(originalPacket: ByteArray, originalLength: Int): ByteArray {
        if (originalLength < 40 || originalLength > 65500 || originalPacket.size < originalLength) return ByteArray(0)
        val originalIpHeaderLength = 40
        val icmpPayloadLen = originalIpHeaderLength + 8
        val actualIcmpPayloadLen = minOf(icmpPayloadLen, originalLength)
        
        val totalLength = 40 + 8 + actualIcmpPayloadLen // IPv6 Header + ICMPv6 Header + Payload
        val buffer = bufferTL.get() ?: ByteBuffer.allocate(65535).also { bufferTL.set(it) }
        buffer.clear()
        
        // IPv6 Header
        buffer.putInt((6 shl 28)) // Version 6, Traffic Class 0, Flow Label 0
        buffer.putShort((8 + actualIcmpPayloadLen).toShort()) // Payload Length
        buffer.put(58.toByte()) // Next Header: ICMPv6
        buffer.put(64.toByte()) // Hop Limit
        
        // Swap src/dst
        for (i in 24..39) buffer.put(originalPacket[i]) // new src = old dst
        for (i in 8..23) buffer.put(originalPacket[i]) // new dst = old src
        
        // ICMPv6 Header
        buffer.put(1.toByte()) // Type 1: Destination Unreachable
        buffer.put(4.toByte()) // Code 4: Port Unreachable
        val icmpChecksumPos = buffer.position()
        buffer.putShort(0.toShort()) // Checksum placeholder
        buffer.putInt(0) // Unused
        
        // ICMPv6 Payload
        buffer.put(originalPacket, 0, actualIcmpPayloadLen)
        
        // Calculate ICMPv6 Checksum (requires pseudo-header)
        var icmpSum = 0
        
        // Pseudo-header: Src IP, Dst IP
        for (i in 8..39) {
            val idx = if (i >= 24) i - 16 else i + 16 // swapped addresses
            val byteVal = originalPacket[idx].toInt() and 0xFF
            if (i % 2 == 0) {
                icmpSum += (byteVal shl 8)
            } else {
                icmpSum += byteVal
            }
        }
        
        // Pseudo-header: Payload Length (32-bit)
        val payloadLen = 8 + actualIcmpPayloadLen
        icmpSum += (payloadLen shr 16) and 0xFFFF
        icmpSum += payloadLen and 0xFFFF
        
        // Pseudo-header: Next Header (24 bits zero, 8 bits protocol)
        icmpSum += 58 // ICMPv6 protocol number
        
        // ICMPv6 Header & Payload
        val icmpDataOffset = 40
        val icmpDataLen = totalLength - 40
        for (i in 0 until icmpDataLen / 2) {
            val word = ((buffer.get(icmpDataOffset + i * 2).toInt() and 0xFF) shl 8) or (buffer.get(icmpDataOffset + i * 2 + 1).toInt() and 0xFF)
            icmpSum += word
        }
        if (icmpDataLen % 2 != 0) {
            val word = (buffer.get(icmpDataOffset + icmpDataLen - 1).toInt() and 0xFF) shl 8
            icmpSum += word
        }
        
        while (icmpSum shr 16 != 0) {
            icmpSum = (icmpSum and 0xFFFF) + (icmpSum shr 16)
        }
        buffer.putShort(icmpChecksumPos, (icmpSum.inv() and 0xFFFF).toShort())
        
        return buffer.array().copyOfRange(0, totalLength)
    }
}

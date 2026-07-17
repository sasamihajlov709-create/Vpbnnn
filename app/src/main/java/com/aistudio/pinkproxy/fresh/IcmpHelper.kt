package com.aistudio.pinkproxy.fresh

import java.nio.ByteBuffer

object IcmpHelper {
    fun createIcmpPortUnreachablePacket(originalPacket: ByteArray, originalLength: Int): ByteArray {
        val originalIpHeaderLength = (originalPacket[0].toInt() and 0x0F) * 4
        
        // ICMP payload requires original IP header + 8 bytes of original payload
        val icmpPayloadLen = originalIpHeaderLength + 8
        val actualIcmpPayloadLen = minOf(icmpPayloadLen, originalLength)
        
        val totalLength = 20 + 8 + actualIcmpPayloadLen
        val buffer = ByteBuffer.allocate(totalLength)
        
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
        val ipHeader = buffer.array().copyOfRange(0, 20)
        var sum = 0
        for (i in 0 until 10) {
            val word = ((ipHeader[i * 2].toInt() and 0xFF) shl 8) or (ipHeader[i * 2 + 1].toInt() and 0xFF)
            sum += word
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        buffer.putShort(ipChecksumPos, (sum.inv() and 0xFFFF).toShort())
        
        // ICMP Header
        buffer.put(3.toByte()) // Type 3: Destination Unreachable
        buffer.put(3.toByte()) // Code 3: Port Unreachable
        val icmpChecksumPos = buffer.position()
        buffer.putShort(0.toShort()) // Checksum placeholder
        buffer.putInt(0) // Unused
        
        // ICMP Payload
        buffer.put(originalPacket, 0, actualIcmpPayloadLen)
        
        // Calculate ICMP Checksum
        val icmpData = buffer.array().copyOfRange(20, totalLength)
        var icmpSum = 0
        for (i in 0 until icmpData.size / 2) {
            val word = ((icmpData[i * 2].toInt() and 0xFF) shl 8) or (icmpData[i * 2 + 1].toInt() and 0xFF)
            icmpSum += word
        }
        if (icmpData.size % 2 != 0) {
            val word = (icmpData.last().toInt() and 0xFF) shl 8
            icmpSum += word
        }
        while (icmpSum shr 16 != 0) {
            icmpSum = (icmpSum and 0xFFFF) + (icmpSum shr 16)
        }
        buffer.putShort(icmpChecksumPos, (icmpSum.inv() and 0xFFFF).toShort())
        
        return buffer.array()
    }
}

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
        val buffer = bufferTL.get()!!
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
        val buffer = bufferTL.get()!!
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

    fun createIcmpPortUnreachablePacket(originalPacket: ByteArray, originalLength: Int): ByteArray {
        val originalIpHeaderLength = (originalPacket[0].toInt() and 0x0F) * 4
        
        // ICMP payload requires original IP header + 8 bytes of original payload
        val icmpPayloadLen = originalIpHeaderLength + 8
        val actualIcmpPayloadLen = minOf(icmpPayloadLen, originalLength)
        
        val totalLength = 20 + 8 + actualIcmpPayloadLen
        val buffer = bufferTL.get()!!
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
        val originalIpHeaderLength = 40
        val icmpPayloadLen = originalIpHeaderLength + 8
        val actualIcmpPayloadLen = minOf(icmpPayloadLen, originalLength)
        
        val totalLength = 40 + 8 + actualIcmpPayloadLen // IPv6 Header + ICMPv6 Header + Payload
        val buffer = bufferTL.get()!!
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

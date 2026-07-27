package com.aistudio.pinkproxy.fresh

import java.net.InetAddress
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.ByteArrayInputStream

object DnsPacketEngine {

    fun buildDnsQuery(host: String, type: Int, id: Int = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000)): ByteArray {
        val bos = ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(bos)
        
        dos.writeShort(id) // ID
        dos.writeShort(0x0100) // Flags: Standard query, RD=1
        dos.writeShort(1) // Questions
        dos.writeShort(0) // Answer RRs
        dos.writeShort(0) // Authority RRs
        dos.writeShort(0) // Additional RRs
        
        val labels = host.split(".")
        for (label in labels) {
            val bytes = label.toByteArray(java.nio.charset.StandardCharsets.UTF_8)
            dos.writeByte(bytes.size)
            dos.write(bytes)
        }
        dos.writeByte(0) // End of name
        
        dos.writeShort(type) // Type
        dos.writeShort(1)    // Class IN
        
        // Add EDNS0 with ECS (Client Subnet) for better CDN routing
        dos.writeShort(0) // Name: root
        dos.writeShort(41) // Type: OPT
        dos.writeShort(4096) // UDP payload size
        dos.writeByte(0) // Higher bits of extended RCODE
        dos.writeByte(0) // EDNS version
        dos.writeShort(0) // Z (flags)
        
        // RDLEN
        val ecsOption = buildEcsOption()
        dos.writeShort(ecsOption.size)
        dos.write(ecsOption)
        
        // Update Additional RRs count (line 19)
        val query = bos.toByteArray()
        query[11] = 1 // ARCOUNT = 1
        return query
    }

    private fun buildEcsOption(): ByteArray {
        val bos = ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(bos)
        dos.writeShort(8) // Option Code: ECS
        dos.writeShort(8) // Option Length
        dos.writeShort(1) // Family: IPv4
        dos.writeByte(24) // Source Mask
        dos.writeByte(0) // Scope Mask
        dos.write(byteArrayOf(1, 1, 1, 0)) // 1.1.1.0/24 as a generic "good" source
        return bos.toByteArray()
    }

    fun parseDnsResponse(data: ByteArray, length: Int, expectedId: Int = -1): List<InetAddress> {
        if (length < 12) return emptyList()
        val ips = mutableListOf<InetAddress>()
        try {
            val dis = DataInputStream(ByteArrayInputStream(data, 0, length))
            val id = dis.readUnsignedShort()
            if (expectedId != -1 && id != expectedId) return emptyList()
            val flags = dis.readUnsignedShort()
            val qCount = dis.readUnsignedShort()
            val aCount = dis.readUnsignedShort()
            dis.skipBytes(4) // Authority and Additional counts
            
            // Skip questions
            for (i in 0 until qCount) {
                skipName(dis, data)
                dis.skipBytes(4) // Type and Class
            }
            
            // Parse answers
            for (i in 0 until aCount) {
                skipName(dis, data)
                val type = dis.readUnsignedShort()
                dis.skipBytes(2) // Class
                dis.skipBytes(4) // TTL
                val rdLen = dis.readUnsignedShort()
                val rData = ByteArray(rdLen)
                dis.readFully(rData)
                
                if (type == 1 && rdLen == 4) { // A
                    ips.add(InetAddress.getByAddress(rData))
                } else if (type == 28 && rdLen == 16) { // AAAA
                    ips.add(InetAddress.getByAddress(rData))
                }
            }
        } catch (e: Exception) {
            // Ignore parse errors
        }
        return ips
    }

    private fun skipName(dis: DataInputStream, data: ByteArray) {
        var b = dis.readUnsignedByte()
        while (b != 0) {
            if ((b and 0xC0) == 0xC0) { // Pointer
                dis.skipBytes(1)
                break
            } else {
                dis.skipBytes(b)
                b = dis.readUnsignedByte()
            }
        }
    }
}

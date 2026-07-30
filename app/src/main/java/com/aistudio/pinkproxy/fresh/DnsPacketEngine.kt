package com.aistudio.pinkproxy.fresh

import java.net.InetAddress
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.ByteArrayInputStream

object DnsPacketEngine {

    fun buildDnsQuery(host: String, type: Int, id: Int = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000), mangleCase: Boolean = false): ByteArray {
        val bos = ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(bos)
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        
        dos.writeShort(id) // ID
        dos.writeShort(0x0100) // Flags: Standard query, RD=1
        dos.writeShort(1) // Questions
        dos.writeShort(0) // Answer RRs
        dos.writeShort(0) // Authority RRs
        dos.writeShort(1) // Additional RRs (EDNS0)
        
        val labels = host.split(".")
        for (label in labels) {
            var labelToUse = label
            if (mangleCase) {
                val sb = StringBuilder()
                for (char in label) {
                    if (char in 'a'..'z' || char in 'A'..'Z') {
                        if (rnd.nextBoolean()) {
                            sb.append(char.uppercase())
                        } else {
                            sb.append(char.lowercase())
                        }
                    } else {
                        sb.append(char)
                    }
                }
                labelToUse = sb.toString()
            }
            val bytes = labelToUse.toByteArray(java.nio.charset.StandardCharsets.UTF_8)
            dos.writeByte(bytes.size)
            dos.write(bytes)
        }
        dos.writeByte(0) // End of name
        
        dos.writeShort(type) // Type
        dos.writeShort(1)    // Class IN
        
        // Add EDNS0 with ECS (Client Subnet), Random Padding, and Cookie
        dos.writeShort(0) // Name: root
        dos.writeShort(41) // Type: OPT
        dos.writeShort(4096) // UDP payload size
        dos.writeByte(0) // Higher bits of extended RCODE
        dos.writeByte(0) // EDNS version
        dos.writeShort(if (rnd.nextBoolean()) 0x8000 else 0) // Z (flags) - occasionally set DO (DNSSEC OK)
        
        val ecsOption = buildEcsOption()
        val paddingSize = rnd.nextInt(64, 256) // Even more aggressive padding
        val paddingOption = buildPaddingOption(paddingSize)
        val cookieOption = buildCookieOption()
        val extraOptions = buildRandomOptions()
        
        val totalOptionsLen = ecsOption.size + paddingOption.size + cookieOption.size + extraOptions.size
        dos.writeShort(totalOptionsLen)
        dos.write(ecsOption)
        dos.write(paddingOption)
        dos.write(cookieOption)
        dos.write(extraOptions)
        
        return bos.toByteArray()
    }

    private fun buildCookieOption(): ByteArray {
        val bos = ByteArrayOutputStream(); val dos = java.io.DataOutputStream(bos)
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        dos.writeShort(10) // Option Code: Cookie
        dos.writeShort(8) // Length
        val cookie = ByteArray(8); rnd.nextBytes(cookie)
        dos.write(cookie)
        return bos.toByteArray()
    }

    private fun buildRandomOptions(): ByteArray {
        val bos = ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(bos)
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        if (rnd.nextBoolean()) {
            dos.writeShort(65001) // Experimental code
            dos.writeShort(4)
            dos.writeInt(rnd.nextInt())
        }
        return bos.toByteArray()
    }

    private fun buildPaddingOption(size: Int): ByteArray {
        val bos = ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(bos)
        dos.writeShort(12) // Option Code: Padding
        dos.writeShort(size) // Option Length
        dos.write(ByteArray(size)) // Null padding
        return bos.toByteArray()
    }

    private fun buildEcsOption(): ByteArray {
        val bos = ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(bos)
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        
        dos.writeShort(8) // Option Code: ECS
        dos.writeShort(8) // Option Length
        dos.writeShort(1) // Family: IPv4
        dos.writeByte(24) // Source Mask
        dos.writeByte(0) // Scope Mask
        
        val prefixes = listOf(
            byteArrayOf(1, 1, 1, 0),    // Cloudflare
            byteArrayOf(8, 8, 8, 0),    // Google
            byteArrayOf(9, 9, 9, 0),    // Quad9
            byteArrayOf(208.toByte(), 67.toByte(), 222.toByte(), 0), // OpenDNS
            byteArrayOf(4, 2, 2, 0),     // Level3
            byteArrayOf(185.toByte(), 199.toByte(), 108.toByte(), 0), // GitHub
            byteArrayOf(104.toByte(), 16.toByte(), 0.toByte(), 0.toByte()),    // Cloudflare range
            byteArrayOf(rnd.nextInt(1, 223).toByte(), rnd.nextInt(256).toByte(), rnd.nextInt(256).toByte(), 0) // Totally random
        )
        dos.write(prefixes.random())
        return bos.toByteArray()
    }

    fun buildDnsQueryTcp(host: String, type: Int, id: Int = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000), mangleCase: Boolean = false): ByteArray {
        val udpQuery = buildDnsQuery(host, type, id, mangleCase)
        val bos = ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(bos)
        dos.writeShort(udpQuery.size)
        dos.write(udpQuery)
        return bos.toByteArray()
    }

    fun parseDnsResponse(data: ByteArray, length: Int, expectedId: Int = -1): List<InetAddress> {
        if (length < 12) return emptyList()
        val ips = mutableListOf<InetAddress>()
        try {
            val bb = java.nio.ByteBuffer.wrap(data, 0, length)
            val id = bb.short.toInt() and 0xFFFF
            if (expectedId != -1 && id != expectedId) return emptyList()
            val flags = bb.short.toInt() and 0xFFFF
            val qCount = bb.short.toInt() and 0xFFFF
            val aCount = bb.short.toInt() and 0xFFFF
            bb.position(bb.position() + 4) // Skip Authority and Additional counts
            
            // Skip questions
            for (i in 0 until qCount) {
                skipName(bb)
                bb.position(bb.position() + 4) // Type and Class
            }
            
            // Parse answers
            for (i in 0 until aCount) {
                skipName(bb)
                val type = bb.short.toInt() and 0xFFFF
                bb.position(bb.position() + 2) // Class
                bb.position(bb.position() + 4) // TTL
                val rdLen = bb.short.toInt() and 0xFFFF
                
                if ((type == 1 && rdLen == 4) || (type == 28 && rdLen == 16)) {
                    val rData = ByteArray(rdLen)
                    bb.get(rData)
                    ips.add(InetAddress.getByAddress(rData))
                } else if (type == 5) { // CNAME
                    // Skip CNAME data
                    bb.position(bb.position() + rdLen)
                } else {
                    bb.position(bb.position() + rdLen)
                }
            }
        } catch (e: Throwable) {
            // Ignore parse errors
        }
        return ips
    }

    data class DnsRecord(val address: InetAddress, val ttlSeconds: Long, val type: Int = 1)

    fun parseDnsResponseDetailed(data: ByteArray, length: Int, expectedId: Int = -1): List<DnsRecord> {
        if (length < 12) return emptyList()
        val records = mutableListOf<DnsRecord>()
        try {
            val bb = java.nio.ByteBuffer.wrap(data, 0, length)
            val id = bb.short.toInt() and 0xFFFF
            if (expectedId != -1 && id != expectedId) return emptyList()
            val flags = bb.short.toInt() and 0xFFFF
            val qCount = bb.short.toInt() and 0xFFFF
            val aCount = bb.short.toInt() and 0xFFFF
            bb.position(bb.position() + 4) // Skip Authority and Additional counts
            
            for (i in 0 until qCount) {
                skipName(bb)
                bb.position(bb.position() + 4)
            }
            
            for (i in 0 until aCount) {
                skipName(bb)
                val type = bb.short.toInt() and 0xFFFF
                bb.position(bb.position() + 2) // Class
                val ttl = bb.int.toLong() and 0xFFFFFFFFL
                val rdLen = bb.short.toInt() and 0xFFFF
                
                if ((type == 1 && rdLen == 4) || (type == 28 && rdLen == 16)) {
                    val rData = ByteArray(rdLen)
                    bb.get(rData)
                    records.add(DnsRecord(InetAddress.getByAddress(rData), ttl, type))
                } else if (type == 65) { // HTTPS Record
                    // We don't parse full SvcParam yet, but we record the presence
                    bb.position(bb.position() + rdLen)
                    records.add(DnsRecord(InetAddress.getByName("0.0.0.0"), ttl, 65))
                } else {
                    bb.position(bb.position() + rdLen)
                }
            }
        } catch (e: Throwable) {}
        return records
    }

    private fun skipName(bb: java.nio.ByteBuffer) {
        var b = bb.get().toInt() and 0xFF
        while (b != 0) {
            if ((b and 0xC0) == 0xC0) { // Pointer
                bb.get() // Skip the second byte of pointer
                break
            } else {
                bb.position(bb.position() + b)
                b = bb.get().toInt() and 0xFF
            }
        }
    }
}

package com.aistudio.pinkproxy.fresh

import java.net.InetAddress

object DnsUtils {
    data class ParsedDnsQuery(val qname: String, val qtype: Int)

    fun parseDnsQName(payload: ByteArray): ParsedDnsQuery? {
        try {
            if (payload.size < 13) return null
            val qcount = ((payload[4].toInt() and 0xFF) shl 8) or (payload[5].toInt() and 0xFF)
            if (qcount <= 0) return null
            
            val sb = StringBuilder()
            var pos = 12
            while (pos < payload.size) {
                val len = payload[pos].toInt() and 0xFF
                if (len == 0) break
                if (sb.isNotEmpty()) sb.append(".")
                if (pos + 1 + len > payload.size) return null
                sb.append(String(payload, pos + 1, len))
                pos += (len + 1)
            }
            if (pos + 2 < payload.size) {
                val qtype = ((payload[pos + 1].toInt() and 0xFF) shl 8) or (payload[pos + 2].toInt() and 0xFF)
                return ParsedDnsQuery(sb.toString(), qtype)
            }
            return ParsedDnsQuery(sb.toString(), 1)
        } catch (e: Exception) { return null }
    }

    fun buildDnsReply(query: ByteArray, ips: List<String>, isIpv6: Boolean): ByteArray {
        val bos = java.io.ByteArrayOutputStream()
        // ID
        bos.write(query.getOrNull(0)?.toInt() ?: 0)
        bos.write(query.getOrNull(1)?.toInt() ?: 0)
        // Flags: Standard query response, No error
        bos.write(0x81)
        bos.write(0x80)
        // Questions count
        bos.write(0)
        bos.write(1)
        // Answer count
        bos.write((ips.size shr 8) and 0xFF)
        bos.write(ips.size and 0xFF)
        // Authority / Additional
        bos.write(0); bos.write(0)
        bos.write(0); bos.write(0)
        
        // Copy Question section
        var pos = 12
        while (pos < query.size) {
            val len = query[pos].toInt() and 0xFF
            if (len == 0) {
                bos.write(0)
                // Type (A = 1, AAAA = 28) and Class IN (0x0001)
                bos.write(query.getOrNull(pos + 1)?.toInt() ?: 0)
                bos.write(query.getOrNull(pos + 2)?.toInt() ?: 0)
                bos.write(query.getOrNull(pos + 3)?.toInt() ?: 0)
                bos.write(query.getOrNull(pos + 4)?.toInt() ?: 0)
                break
            }
            bos.write(len)
            if (pos + 1 + len <= query.size) {
                bos.write(query, pos + 1, len)
            } else {
                val available = (query.size - (pos + 1)).coerceAtLeast(0)
                if (available > 0) {
                    bos.write(query, pos + 1, available)
                }
            }
            pos += (len + 1)
        }
        
        // Answers
        for (ip in ips) {
            // Name: pointer to offset 12 (0xc00c)
            bos.write(0xc0)
            bos.write(0x0c)
            if (isIpv6) {
                // Type AAAA (28 = 0x001c)
                bos.write(0); bos.write(28)
                // Class IN
                bos.write(0); bos.write(1)
                // TTL (60s)
                bos.write(0); bos.write(0); bos.write(0); bos.write(60)
                // Data length (16 bytes for IPv6)
                bos.write(0); bos.write(16)
                // Parse and write IPv6 safely
                val addr = try { InetAddress.getByName(ip) } catch (e: Exception) { null }
                if (addr != null) {
                    bos.write(addr.address)
                } else {
                    bos.write(ByteArray(16))
                }
            } else {
                // Type A (1 = 0x0001)
                bos.write(0); bos.write(1)
                // Class IN
                bos.write(0); bos.write(1)
                // TTL (60s)
                bos.write(0); bos.write(0); bos.write(0); bos.write(60)
                // Data length (4 bytes for IPv4)
                bos.write(0); bos.write(4)
                // IP address safely
                val addr = try { InetAddress.getByName(ip) } catch (e: Exception) { null }
                if (addr != null) {
                    bos.write(addr.address)
                } else {
                    bos.write(ByteArray(4))
                }
            }
        }
        return bos.toByteArray()
    }
}

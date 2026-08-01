package com.aistudio.pinkproxy.fresh

import java.net.InetAddress

object DnsUtils {
    data class ParsedDnsQuery(val qname: String, val qtype: Int)

    fun parseDnsQName(payload: ByteArray, offset: Int = 0, length: Int = payload.size): ParsedDnsQuery? {
        try {
            if (length < 13) return null
            val qcount = ((payload[offset + 4].toInt() and 0xFF) shl 8) or (payload[offset + 5].toInt() and 0xFF)
            if (qcount <= 0) return null
            
            val sb = StringBuilder()
            var pos = offset + 12
            val limit = offset + length
            while (pos < limit) {
                val len = payload[pos].toInt() and 0xFF
                if (len == 0) break
                if (sb.isNotEmpty()) sb.append(".")
                if (pos + 1 + len > limit) return null
                sb.append(String(payload, pos + 1, len))
                pos += (len + 1)
            }
            if (pos + 2 < limit) {
                val qtype = ((payload[pos + 1].toInt() and 0xFF) shl 8) or (payload[pos + 2].toInt() and 0xFF)
                return ParsedDnsQuery(sb.toString(), qtype)
            }
            return ParsedDnsQuery(sb.toString(), 1)
        } catch (e: Throwable) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}"); return null }
    }

    fun buildDnsReply(query: ByteArray, queryOffset: Int, queryLength: Int, ips: List<String>, isIpv6: Boolean): ByteArray {
        val parsedAddrs = ips.mapNotNull { ip ->
            try {
                val addr = InetAddress.getByName(ip)
                if (isIpv6 && addr is java.net.Inet6Address) addr
                else if (!isIpv6 && addr is java.net.Inet4Address) addr
                else null
            } catch (e: Throwable) { null }
        }

        val bos = java.io.ByteArrayOutputStream()
        val limit = queryOffset + queryLength
        // ID
        bos.write(if (queryOffset < limit) query[queryOffset].toInt() else 0)
        bos.write(if (queryOffset + 1 < limit) query[queryOffset + 1].toInt() else 0)
        // Flags: Standard query response, No error
        bos.write(0x81)
        bos.write(0x80)
        // Questions count
        bos.write(0)
        bos.write(1)
        // Answer count
        bos.write((parsedAddrs.size shr 8) and 0xFF)
        bos.write(parsedAddrs.size and 0xFF)
        // Authority / Additional
        bos.write(0); bos.write(0)
        bos.write(0); bos.write(0)
        
        // Copy Question section
        var pos = queryOffset + 12
        while (pos < limit) {
            val len = query[pos].toInt() and 0xFF
            if (len == 0) {
                bos.write(0)
                // Type (A = 1, AAAA = 28) and Class IN (0x0001)
                bos.write(if (pos + 1 < limit) query[pos + 1].toInt() else 0)
                bos.write(if (pos + 2 < limit) query[pos + 2].toInt() else 0)
                bos.write(if (pos + 3 < limit) query[pos + 3].toInt() else 0)
                bos.write(if (pos + 4 < limit) query[pos + 4].toInt() else 0)
                break
            }
            bos.write(len)
            if (pos + 1 + len <= limit) {
                bos.write(query, pos + 1, len)
            } else {
                val available = (limit - (pos + 1)).coerceAtLeast(0)
                if (available > 0) {
                    bos.write(query, pos + 1, available)
                }
            }
            pos += (len + 1)
        }

        
        // Answers
        for (addr in parsedAddrs) {
            // Name: pointer to offset 12 (0xc00c)
            bos.write(0xc0)
            bos.write(0x0c)
            val bytes = addr.address
            if (isIpv6) {
                // Type AAAA (28 = 0x001c)
                bos.write(0); bos.write(28)
                // Class IN
                bos.write(0); bos.write(1)
                // TTL (dynamic based on censorship)
                val ttl = (DnsCacheManager.getDynamicTtl() / 1000L).toInt()
                bos.write((ttl shr 24) and 0xFF)
                bos.write((ttl shr 16) and 0xFF)
                bos.write((ttl shr 8) and 0xFF)
                bos.write(ttl and 0xFF)
                // Data length (16 bytes for IPv6)
                bos.write(0); bos.write(16)
                bos.write(bytes)
            } else {
                // Type A (1 = 0x0001)
                bos.write(0); bos.write(1)
                // Class IN
                bos.write(0); bos.write(1)
                // TTL (dynamic based on censorship)
                val ttl4 = (DnsCacheManager.getDynamicTtl() / 1000L).toInt()
                bos.write((ttl4 shr 24) and 0xFF)
                bos.write((ttl4 shr 16) and 0xFF)
                bos.write((ttl4 shr 8) and 0xFF)
                bos.write(ttl4 and 0xFF)
                // Data length (4 bytes for IPv4)
                bos.write(0); bos.write(4)
                bos.write(bytes)
            }
        }
        return bos.toByteArray()
    }
}

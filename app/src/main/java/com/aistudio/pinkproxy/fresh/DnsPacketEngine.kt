package com.aistudio.pinkproxy.fresh

import java.net.InetAddress
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.ByteArrayInputStream

object DnsPacketEngine {

    fun buildDnsQuery(host: String, type: Int, id: Int = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000), mangleCase: Boolean = false): ByteArray {
        val buffer = ProxyStats.obtain8k()
        try {
            val bb = java.nio.ByteBuffer.wrap(buffer)
            val rnd = java.util.concurrent.ThreadLocalRandom.current()
            
            bb.putShort(id.toShort()) // ID
            bb.putShort(0x0100.toShort()) // Flags: Standard query, RD=1
            bb.putShort(1.toShort()) // Questions
            bb.putShort(0.toShort()) // Answer RRs
            bb.putShort(0.toShort()) // Authority RRs
            bb.putShort(1.toShort()) // Additional RRs (EDNS0)
            
            val labels = host.split(".")
            for (label in labels) {
                var labelToUse = label
                if (mangleCase) {
                    val sb = StringBuilder()
                    for (char in label) {
                        if (char in 'a'..'z' || char in 'A'..'Z') {
                            if (rnd.nextBoolean()) sb.append(char.uppercase()) else sb.append(char.lowercase())
                        } else sb.append(char)
                    }
                    labelToUse = sb.toString()
                }
                val bytes = labelToUse.toByteArray(java.nio.charset.StandardCharsets.UTF_8)
                bb.put(bytes.size.toByte())
                bb.put(bytes)
            }
            bb.put(0.toByte()) // End of name
            
            bb.putShort(type.toShort()) // Type
            bb.putShort(1.toShort())    // Class IN
            
            // EDNS0
            bb.put(0.toByte()) // Name: root
            bb.putShort(41.toShort()) // Type: OPT
            bb.putShort(4096.toShort()) // UDP payload size
            bb.put(0.toByte()) // RCODE
            bb.put(0.toByte()) // Version
            bb.putShort((if (rnd.nextBoolean()) 0x8000 else 0).toShort()) // Z (flags)
            
            val ecsOptionStart = bb.position()
            buildEcsOption(bb)
            val paddingSize = rnd.nextInt(64, 256)
            buildPaddingOption(bb, paddingSize)
            buildCookieOption(bb)
            buildRandomOptions(bb)
            val totalOptionsLen = bb.position() - ecsOptionStart
            
            val currentPos = bb.position()
            bb.position(ecsOptionStart - 2)
            bb.putShort(totalOptionsLen.toShort())
            bb.position(currentPos)
            
            val result = ByteArray(bb.position())
            System.arraycopy(buffer, 0, result, 0, bb.position())
            return result
        } finally {
            ProxyStats.release8k(buffer)
        }
    }

    private fun buildCookieOption(bb: java.nio.ByteBuffer) {
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        bb.putShort(10.toShort()) // Option Code: Cookie
        bb.putShort(8.toShort()) // Length
        val cookie = ByteArray(8); rnd.nextBytes(cookie)
        bb.put(cookie)
    }

    private fun buildRandomOptions(bb: java.nio.ByteBuffer) {
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        if (rnd.nextBoolean()) {
            bb.putShort(65001.toShort()) // Experimental code
            bb.putShort(4.toShort())
            bb.putInt(rnd.nextInt())
        }
    }

    private fun buildPaddingOption(bb: java.nio.ByteBuffer, size: Int) {
        bb.putShort(12.toShort()) // Option Code: Padding
        bb.putShort(size.toShort()) // Option Length
        bb.put(ByteArray(size)) // Null padding
    }

    private fun buildEcsOption(bb: java.nio.ByteBuffer) {
        val rnd = java.util.concurrent.ThreadLocalRandom.current()
        bb.putShort(8.toShort()) // Option Code: ECS
        bb.putShort(8.toShort()) // Option Length
        bb.putShort(1.toShort()) // Family: IPv4
        bb.put(24.toByte()) // Source Mask
        bb.put(0.toByte()) // Scope Mask
        
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
        bb.put(prefixes.random())
    }

    fun buildDnsQueryTcp(host: String, type: Int, id: Int = java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000), mangleCase: Boolean = false): ByteArray {
        val udpQuery = buildDnsQuery(host, type, id, mangleCase)
        val result = ByteArray(udpQuery.size + 2)
        result[0] = (udpQuery.size shr 8).toByte()
        result[1] = (udpQuery.size and 0xFF).toByte()
        System.arraycopy(udpQuery, 0, result, 2, udpQuery.size)
        return result
    }

    fun parseDnsResponse(data: ByteArray, length: Int, expectedId: Int = -1): List<InetAddress> {
        if (length < 12) return emptyList()
        val ips = mutableListOf<InetAddress>()
        try {
            // Quick fingerprint check: must have QR=1 (response)
            if ((data[2].toInt() and 0x80) == 0) return emptyList()
            
            val id = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
            if (expectedId != -1 && id != expectedId) return emptyList()
            
            val qCount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
            val aCount = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
            
            val bb = java.nio.ByteBuffer.wrap(data, 0, length)
            bb.position(12)
            
            // Skip questions
            for (i in 0 until qCount) {
                if (!bb.hasRemaining()) break
                skipName(bb)
                if (bb.remaining() >= 4) {
                    bb.position(bb.position() + 4) // Type and Class
                } else {
                    bb.position(length)
                }
            }
            
            // Parse answers
            for (i in 0 until aCount) {
                if (!bb.hasRemaining()) break
                skipName(bb)
                if (bb.remaining() < 10) break
                val type = bb.short.toInt() and 0xFFFF
                bb.position(bb.position() + 2) // Class
                bb.position(bb.position() + 4) // TTL
                val rdLen = bb.short.toInt() and 0xFFFF
                
                if (bb.remaining() < rdLen) break
                if ((type == 1 && rdLen == 4) || (type == 28 && rdLen == 16)) {
                    val rData = ByteArray(rdLen)
                    bb.get(rData)
                    ips.add(InetAddress.getByAddress(rData))
                } else {
                    bb.position(bb.position() + rdLen)
                }
            }
        } catch (e: Throwable) {
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
                if (!bb.hasRemaining()) break
                skipName(bb)
                if (bb.remaining() >= 4) {
                    bb.position(bb.position() + 4)
                }
            }
            
            for (i in 0 until aCount) {
                if (!bb.hasRemaining()) break
                skipName(bb)
                if (bb.remaining() < 10) break
                val type = bb.short.toInt() and 0xFFFF
                bb.position(bb.position() + 2) // Class
                val ttl = bb.int.toLong() and 0xFFFFFFFFL
                val rdLen = bb.short.toInt() and 0xFFFF
                
                if (bb.remaining() < rdLen) break
                
                if ((type == 1 && rdLen == 4) || (type == 28 && rdLen == 16)) {
                    val rData = ByteArray(rdLen)
                    bb.get(rData)
                    records.add(DnsRecord(InetAddress.getByAddress(rData), ttl, type))
                } else if (type == 65) { // HTTPS Record
                    val startPos = bb.position()
                    try {
                        if (bb.remaining() >= 2) {
                            bb.position(bb.position() + 2) // Skip SvcPriority
                            skipName(bb) // Skip TargetName
                            
                            var paramsProcessed = 0
                            while (bb.position() < startPos + rdLen && paramsProcessed < 20) {
                                if (bb.remaining() < 4) break
                                val paramKey = bb.short.toInt() and 0xFFFF
                                val paramLen = bb.short.toInt() and 0xFFFF
                                if (bb.remaining() < paramLen) break
                                
                                if (paramKey == 5) { // ECH (Encrypted Client Hello)
                                    records.add(DnsRecord(InetAddress.getByName("0.0.0.1"), ttl, 65)) // Use special IP as flag
                                    bb.position(bb.position() + paramLen)
                                } else {
                                    bb.position(bb.position() + paramLen)
                                }
                                paramsProcessed++
                            }
                        }
                    } catch (e: Throwable) {
                    } finally {
                        bb.position(minOf(startPos + rdLen, length))
                    }
                } else {
                    bb.position(bb.position() + rdLen)
                }
            }
        } catch (e: Throwable) {}
        return records
    }

    private val suspiciousIps = setOf(
        "127.0.0.1", "0.0.0.0",
        "10.10.10.10", "1.2.3.4", "10.10.34.34", "10.10.34.35",
        "127.0.0.53", "127.0.0.54", "0.0.0.1",
        "146.112.61.106", "146.112.61.104", "146.112.61.105", // Cisco Umbrella
        "188.114.96.0", "188.114.97.0", "188.114.98.0", "188.114.99.0",
        "31.13.71.36", "31.13.72.36", "31.13.73.36", // Facebook redirections
        "77.88.8.8", "77.88.8.1", "213.180.204.3", "213.180.193.3", // Yandex
        "95.167.13.50", "95.167.13.49", // Rostelecom
        "195.82.146.120", "195.82.146.114", // Megafon
        "212.188.7.20", "217.16.20.12", // MTS
        "8.254.218.126", "204.232.175.78", "198.101.242.72",
        "93.184.216.34", "103.224.212.222", "127.42.42.42",
        "37.1.201.123", "37.1.201.124", "37.1.201.125", // More local redirects
        "109.239.142.158", "109.239.142.159",
        "127.0.0.1", "0.0.0.0", "::1",
        "213.180.204.62", "213.180.193.62", // Yandex safe search redirects
        "77.88.21.11", "77.88.21.12",
        "146.112.61.106" // OpenDNS block page
    )

    private val canaryDomains = setOf(
        "youtube.com", "google.com", "facebook.com", "instagram.com", "twitter.com", 
        "t.me", "telegram.org", "discord.com", "chatgpt.com", "github.com"
    )

    fun isSuspicious(address: InetAddress, host: String = "", ttl: Long = -1): Boolean {
        val hostAddress = address.hostAddress ?: return true
        if (suspiciousIps.contains(hostAddress)) return true
        
        // TTL Analysis:Spoofed DNS responses from DPI often have very low TTL (1 or 0)
        // to avoid long-term cache poisoning while still disrupting the current request.
        if (ttl != -1L && ttl <= 1L) return true

        // If it's a known canary domain and resolves to something VERY suspicious (like private IP)
        if (canaryDomains.any { host.contains(it, ignoreCase = true) }) {
            if (address.isSiteLocalAddress || address.isLoopbackAddress || address.isAnyLocalAddress || hostAddress.startsWith("10.") || hostAddress.startsWith("127.")) {
                return true
            }
        }
        
        // Check for local network redirects which shouldn't happen for global domains
        if (address.isLoopbackAddress || address.isAnyLocalAddress || address.isLinkLocalAddress || address.isSiteLocalAddress) {
            return true
        }
        return false
    }

    private fun skipName(bb: java.nio.ByteBuffer) {
        val limit = bb.limit()
        var depth = 0
        while (depth < 40) {
            if (!bb.hasRemaining()) break
            val b = bb.get().toInt() and 0xFF
            if (b == 0) break
            
            if ((b and 0xC0) == 0xC0) { // Pointer
                if (bb.hasRemaining()) {
                    bb.get() 
                }
                break
            } else {
                val newPos = bb.position() + b
                if (newPos <= limit) {
                    bb.position(newPos)
                } else {
                    bb.position(limit)
                    break
                }
            }
            depth++
        }
    }
}

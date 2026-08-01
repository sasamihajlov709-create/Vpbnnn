package com.aistudio.pinkproxy.fresh

import android.net.VpnService
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object DnsInterceptor {
    suspend fun intercept(payload: ByteArray, vpnService: VpnService?): ByteArray? = withContext(ProxyDispatcher.io) {
        if (payload.size < 12) return@withContext null
        
        try {
            val bb = ByteBuffer.wrap(payload)
            val id = bb.short
            val flags = bb.short.toInt() and 0xFFFF
            
            // Check if it's a query (QR bit = 0)
            if ((flags and 0x8000) != 0) return@withContext null
            
            val qdcount = bb.short.toInt() and 0xFFFF
            if (qdcount != 1) return@withContext null
            
            bb.short // ancount
            bb.short // nscount
            bb.short // arcount
            
            // Parse QNAME
            val domainBuilder = java.lang.StringBuilder()
            var len = bb.get().toInt() and 0xFF
            while (len > 0) {
                if ((len and 0xC0) == 0xC0) {
                    // Pointer, ignore for simple query parser
                    bb.get()
                    break
                }
                val label = ByteArray(len)
                bb.get(label)
                domainBuilder.append(String(label)).append(".")
                len = bb.get().toInt() and 0xFF
            }
            if (domainBuilder.isNotEmpty() && domainBuilder.last() == '.') {
                domainBuilder.deleteCharAt(domainBuilder.length - 1)
            }
            val domain = domainBuilder.toString()
            
            val qtype = bb.short.toInt() and 0xFFFF
            val qclass = bb.short.toInt() and 0xFFFF
            val queryEndPos = bb.position()
            
            if (qclass != 1) return@withContext null // Only IN class
            
            if (qtype != 1 && qtype != 28) {
                return@withContext buildResponse(payload, id, queryEndPos, emptyList())
            }
            
            // Resolve using RobustResolver
            val ips = RobustResolver.resolve(domain, vpnService)
            
            // Filter IPv4/IPv6 based on QTYPE
            val filteredIps = if (qtype == 1) {
                ips.filterIsInstance<Inet4Address>()
            } else {
                ips.filterIsInstance<Inet6Address>()
            }
            
            return@withContext buildResponse(payload, id, queryEndPos, filteredIps)
        } catch (e: Throwable) {
            return@withContext null
        }
    }
    
    private fun buildResponse(query: ByteArray, id: Short, queryEndPos: Int, ips: List<InetAddress>): ByteArray {
        val bos = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(bos)
        
        dos.writeShort(id.toInt())
        dos.writeShort(0x8180) // Standard query response, No error
        dos.writeShort(1) // QDCOUNT
        dos.writeShort(ips.size) // ANCOUNT
        dos.writeShort(0) // NSCOUNT
        dos.writeShort(0) // ARCOUNT
        
        // Write the query back
        dos.write(query, 12, queryEndPos - 12)
        
        // Write answers
        for (ip in ips) {
            dos.writeShort(0xC00C) // Name pointer to the query name
            val type = if (ip is Inet4Address) 1 else 28
            dos.writeShort(type)
            dos.writeShort(1) // IN class
            dos.writeInt(600) // TTL 10 minutes
            val addr = ip.address
            dos.writeShort(addr.size)
            dos.write(addr)
        }
        
        return bos.toByteArray()
    }
}

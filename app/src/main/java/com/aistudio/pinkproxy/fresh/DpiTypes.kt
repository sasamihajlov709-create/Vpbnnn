package com.aistudio.pinkproxy.fresh

enum class DpiType {
    NONE,
    TCP_RESET,
    UDP_BLOCK,
    TLS_SNI_BLOCK,
    DNS_POISONING,
    CONNECTION_TIMEOUT,
    HTTP_BLOCK,
    TLS_HANDSHAKE_TIMEOUT,
    BLACKHOLE,
    TCP_STALL,
    SSL_STALL,
    DNS_VERIFICATION_FAILURE,
    MTU_EXCEEDED
}

enum class DnsType {
    AUTO,
    SYSTEM,
    GOOGLE_DOH,
    CLOUDFLARE_DOH,
    ADGUARD_DOH,
    QUAD9_DOH,
    CUSTOM_DOH,
    CUSTOM_TCP,
    CUSTOM_UDP
}

enum class TransportType {
    TCP,
    UDP,
    DNS;

    val isL4: Boolean get() = this == TCP || this == UDP
    val isDns: Boolean get() = this == DNS
}

/**
 * Resolver transport layer used exclusively by the DNS pipeline.
 * Separates Application Transport (L4 TCP/UDP) from underlying DNS protocol carrier.
 */
enum class DnsResolverTransport(val defaultPort: Int, val isSecure: Boolean) {
    PLAIN_UDP(53, false),
    PLAIN_TCP(53, false),
    DOH(443, true),
    DOT(853, true),
    DOH3(853, true)
}

data class DpiEvent(val type: DpiType, val timestamp: Long = System.currentTimeMillis())

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

data class DpiEvent(val type: DpiType, val timestamp: Long = System.currentTimeMillis())

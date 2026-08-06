package com.aistudio.pinkproxy.fresh

enum class FailureReason {
    TIMEOUT,
    TCP_RESET,
    SSL_HANDSHAKE_ERROR,
    CONNECTION_REFUSED,
    CENSORSHIP_STALL,
    DNS_POISONED,
    MTU_EXCEEDED,
    PROTOCOL_ERROR,
    HANDSHAKE_TIMEOUT,
    UNKNOWN
}

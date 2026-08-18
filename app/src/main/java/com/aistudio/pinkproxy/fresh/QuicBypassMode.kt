package com.aistudio.pinkproxy.fresh

enum class QuicBypassMode {
    /**
     * Obey user-configured bypass rule.
     */
    AUTO,

    /**
     * Explicit user block of all UDP QUIC traffic, forcing client to fallback to TCP.
     */
    FORCE_BLOCK,

    /**
     * Never block QUIC; route through UDP evasion engines.
     */
    FORCE_ALLOW
}

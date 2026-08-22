package com.aistudio.pinkproxy.fresh

/**
 * Granular observation quality tiers representing the confidence and depth of connection success.
 */
enum class ObservationQuality(val weight: Double, val minLevelForHostMemory: Boolean) {
    CONNECT_ONLY(0.0, false),               // TCP SYN-ACK only - does not prove bypass
    TLS_RECORD_RECEIVED(0.1, false),        // Initial TLS/HTTP response chunk received (weak bypass signal)
    SERVER_HELLO_RECEIVED(0.5, false),      // Handshake in progress, got Server Hello
    HANDSHAKE_COMPLETE(1.0, true),          // Cryptographic handshake / full TLS session established
    APPLICATION_DATA_EXCHANGED(2.0, true),  // Valid application payload transferred without RST/stall
    SUSTAINED_DATA_TRANSFER(3.0, true);     // Sustained high-volume streaming confirmed (highest confidence)

    companion object {
        // Compatibility alias
        val FULL_DATA_TRANSFER = APPLICATION_DATA_EXCHANGED
    }
}

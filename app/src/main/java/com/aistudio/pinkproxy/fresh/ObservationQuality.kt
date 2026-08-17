package com.aistudio.pinkproxy.fresh

/**
 * Granular observation quality tiers representing the confidence and depth of connection success.
 */
enum class ObservationQuality(val weight: Double, val minLevelForHostMemory: Boolean) {
    CONNECT_ONLY(0.05, false),               // TCP SYN-ACK only - does not prove bypass
    TLS_RECORD_RECEIVED(0.30, false),        // Initial TLS/HTTP response chunk received (weak bypass signal)
    HANDSHAKE_COMPLETE(0.70, true),          // Cryptographic handshake / full TLS session established
    APPLICATION_DATA_EXCHANGED(0.95, true),  // Valid application payload transferred without RST/stall
    SUSTAINED_DATA_TRANSFER(1.00, true);     // Sustained high-volume streaming confirmed (highest confidence)

    companion object {
        // Compatibility alias
        val FULL_DATA_TRANSFER = APPLICATION_DATA_EXCHANGED
    }
}

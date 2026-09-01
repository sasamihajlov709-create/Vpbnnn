package com.aistudio.pinkproxy.fresh

/**
 * Granular observation quality tiers representing the confidence and depth of connection success.
 */
enum class ObservationQuality(val weight: Double, val minLevelForHostMemory: Boolean, val label: String) {
    CONNECT_ONLY(0.3, false, "Probing"),               // TCP SYN-ACK only - does not prove bypass
    TLS_RECORD_RECEIVED(0.4, false, "Viable"),        // Initial TLS/HTTP response chunk received (weak bypass signal)
    SERVER_HELLO_RECEIVED(0.5, false, "Promising"),      // Handshake in progress, got Server Hello
    HANDSHAKE_COMPLETE(0.6, false, "Likely Good"),          // Cryptographic handshake / full TLS session established
    APPLICATION_DATA_EXCHANGED(1.0, true, "Optimal"),  // Valid application payload transferred without RST/stall
    SUSTAINED_DATA_TRANSFER(3.0, true, "Verified");     // Sustained high-volume streaming confirmed (highest confidence)

    companion object {
        // Compatibility alias
        val FULL_DATA_TRANSFER = APPLICATION_DATA_EXCHANGED
    }
}

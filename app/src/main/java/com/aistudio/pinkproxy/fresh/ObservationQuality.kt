package com.aistudio.pinkproxy.fresh

/**
 * Observation quality tiers representing the confidence and depth of connection success.
 */
enum class ObservationQuality(val weight: Double) {
    CONNECT_ONLY(0.10),          // Socket connection established (weak signal)
    TLS_RECORD_RECEIVED(0.40),   // First TLS/HTTP record received
    HANDSHAKE_COMPLETE(0.80),    // Full TLS handshake or initial protocol exchange complete
    FULL_DATA_TRANSFER(1.00)     // Bi-directional application data streaming confirmed (strong signal)
}

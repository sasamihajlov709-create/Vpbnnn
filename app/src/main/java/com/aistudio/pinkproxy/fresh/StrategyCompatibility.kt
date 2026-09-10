package com.aistudio.pinkproxy.fresh

data class StrategyCompatibility(
    val supportedTransports: Set<TransportType> = setOf(TransportType.TCP),
    val requiresPacketEngine: Boolean = false,
    val safeForEncryptedPayload: Boolean = true,
    val preservesProtocolSemantics: Boolean = true
)

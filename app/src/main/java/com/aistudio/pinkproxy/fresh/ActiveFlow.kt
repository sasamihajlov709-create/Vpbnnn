package com.aistudio.pinkproxy.fresh

data class ActiveFlow(
    val id: String,
    val host: String,
    val transport: TransportType,
    val strategy: BypassStrategy,
    val reasoning: String = "",
    val startTime: Long = System.currentTimeMillis(),
    val bytesSent: Long = 0,
    val bytesReceived: Long = 0,
    val status: String = "ACTIVE"
) {
    constructor(
        id: String,
        host: String,
        type: String,
        strategy: BypassStrategy,
        reasoning: String = "",
        startTime: Long = System.currentTimeMillis(),
        bytesSent: Long = 0,
        bytesReceived: Long = 0,
        status: String = "ACTIVE"
    ) : this(
        id = id,
        host = host,
        transport = when (type.uppercase()) {
            "UDP" -> TransportType.UDP
            "DNS" -> TransportType.DNS
            else -> TransportType.TCP
        },
        strategy = strategy,
        reasoning = reasoning,
        startTime = startTime,
        bytesSent = bytesSent,
        bytesReceived = bytesReceived,
        status = status
    )

    val type: String get() = transport.name

    companion object {
        fun fromContext(context: FlowContext, id: String = context.sessionId, reasoning: String = ""): ActiveFlow {
            return ActiveFlow(
                id = id,
                host = context.host,
                transport = context.transport,
                strategy = context.strategy,
                reasoning = reasoning,
                startTime = context.creationTime
            )
        }
    }
}


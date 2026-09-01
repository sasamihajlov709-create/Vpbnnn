import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "r") as f:
    content = f.read()

old_success = """            val reward = when (obs.quality) {
                ObservationQuality.CONNECT_ONLY -> 300L       // 0.3 weight
                ObservationQuality.TLS_RECORD_RECEIVED -> 400L // 0.4 weight
                ObservationQuality.SERVER_HELLO_RECEIVED -> 500L // 0.5 weight
                ObservationQuality.HANDSHAKE_COMPLETE -> 600L  // 0.6 weight
                ObservationQuality.APPLICATION_DATA_EXCHANGED -> 1000L // 1.0 weight
                ObservationQuality.SUSTAINED_DATA_TRANSFER -> 2000L // 2.0 weight
            }"""

new_success = """            val reward = (obs.quality.weight * 1000L).toLong()"""

content = content.replace(old_success, new_success)

old_penalty = """            val penalty = when (obs.failureReason) {
                // Strategy Failures (High Penalty)
                FailureReason.TCP_RESET, FailureReason.SSL_HANDSHAKE_ERROR, FailureReason.CENSORSHIP_STALL, FailureReason.DNS_POISONED, FailureReason.PROTOCOL_ERROR -> 1000L // 1.0 weight
                FailureReason.TIMEOUT, FailureReason.HANDSHAKE_TIMEOUT -> 500L // 0.5 weight
                                
                // Target Failures (Low Penalty, might just be offline server)
                FailureReason.CONNECTION_REFUSED, FailureReason.MTU_EXCEEDED, FailureReason.TARGET_UNAVAILABLE -> 100L // 0.1 weight"""

new_penalty = """            val penalty = when (obs.failureReason) {
                // Strategy Failures (High Penalty)
                FailureReason.TCP_RESET, FailureReason.SSL_HANDSHAKE_ERROR, FailureReason.CENSORSHIP_STALL, FailureReason.DNS_POISONED, FailureReason.PROTOCOL_ERROR -> 1000L // 1.0 weight
                FailureReason.TIMEOUT, FailureReason.HANDSHAKE_TIMEOUT -> 1000L // 1.0 weight
                                
                // Target Failures (Low Penalty, might just be offline server)
                FailureReason.CONNECTION_REFUSED, FailureReason.MTU_EXCEEDED, FailureReason.TARGET_UNAVAILABLE -> 100L // 0.1 weight"""

content = content.replace(old_penalty, new_penalty)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt", "w") as f:
    f.write(content)


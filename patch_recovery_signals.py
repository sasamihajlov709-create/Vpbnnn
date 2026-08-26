import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "r") as f:
    content = f.read()

new_signals = """sealed class RecoverySignal {
    abstract val transport: TransportType?

    interface HostLevelRecoverySignal {
        val host: String?
        val category: HostCategory
    }

    interface TunnelLevelRecoverySignal

    data class DpiDetected(val type: DpiType, override val host: String? = null, override val transport: TransportType, override val category: HostCategory = HostCategory.OTHER) : RecoverySignal(), HostLevelRecoverySignal
    data class TunnelStall(val durationMs: Long, val activeConnections: Int, override val transport: TransportType) : RecoverySignal(), TunnelLevelRecoverySignal
    data class TcpStall(override val host: String, val strategy: BypassStrategy, override val transport: TransportType, override val category: HostCategory = HostCategory.OTHER) : RecoverySignal(), HostLevelRecoverySignal
    data class SslStall(override val host: String, val strategy: BypassStrategy, override val transport: TransportType, override val category: HostCategory = HostCategory.OTHER) : RecoverySignal(), HostLevelRecoverySignal
    data class DnsFailure(val domain: String, val isPoisoned: Boolean, override val transport: TransportType = TransportType.DNS, override val category: HostCategory = HostCategory.OTHER) : RecoverySignal(), HostLevelRecoverySignal {
        override val host: String get() = domain
    }
    data class ProxyUnresponsive(val reason: String, override val transport: TransportType) : RecoverySignal(), TunnelLevelRecoverySignal
    data class MemoryPressure(val usedPercent: Int) : RecoverySignal() {
        override val transport: TransportType? = null
    }
    data class ExtremeLatency(val latencyMs: Long, override val transport: TransportType) : RecoverySignal(), TunnelLevelRecoverySignal
    data class HealthDegraded(val details: String, override val transport: TransportType) : RecoverySignal(), TunnelLevelRecoverySignal
    data class NetworkLost(val networkType: String) : RecoverySignal() {
        override val transport: TransportType? = null
    }
    object ManualReset : RecoverySignal() {
        override val transport: TransportType? = null
    }
}"""

content = re.sub(r'sealed class RecoverySignal \{.*?\n\}', new_signals, content, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "w") as f:
    f.write(content)

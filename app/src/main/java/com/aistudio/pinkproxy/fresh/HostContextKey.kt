package com.aistudio.pinkproxy.fresh

/**
 * Contextual composite key isolating host memory across Transport, Network Profile, and Host Category.
 */
data class HostContextKey(
    val host: String,
    val transport: TransportType,
    val profileId: String
) {
    fun toStorageString(): String = "$host|$transport|$profileId"

    companion object {
        fun fromStorageString(str: String): HostContextKey {
            val parts = str.split("|")
            return if (parts.size >= 3) {
                val host = parts[0]
                val transport = try { TransportType.valueOf(parts[1]) } catch (e: Exception) { TransportType.TCP }
                val profile = parts[2]
                HostContextKey(host, transport, profile)
            } else if (parts.size == 2) {
                val host = parts[0]
                val transport = try { TransportType.valueOf(parts[1]) } catch (e: Exception) { TransportType.TCP }
                HostContextKey(host, transport, "default")
            } else {
                HostContextKey(parts[0], TransportType.TCP, "default")
            }
        }
    }
}

data class HostStrategyBlacklistKey(
    val host: String,
    val transport: TransportType,
    val profileId: String,
    val strategy: BypassStrategy
) {
    fun toStorageString(): String = "$host|$transport|$profileId|${strategy.name}"

    companion object {
        fun fromStorageString(str: String): HostStrategyBlacklistKey? {
            val parts = str.split("|")
            if (parts.size >= 4) {
                val host = parts[0]
                val transport = try { TransportType.valueOf(parts[1]) } catch (e: Exception) { return null }
                val profile = parts[2]
                val strategy = try { BypassStrategy.valueOf(parts[3]) } catch (e: Exception) { return null }
                return HostStrategyBlacklistKey(host, transport, profile, strategy)
            }
            return null
        }
    }
}

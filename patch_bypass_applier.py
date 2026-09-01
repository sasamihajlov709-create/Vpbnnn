import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassApplier.kt", "r") as f:
    content = f.read()

old_apply_tcp = """        val tcpContext = TcpExecutionContext(
            socket = socket,
            output = output,
            data = finalData,
            length = finalLen,
            host = host,
            strategy = strategy,
            config = config,
            effectiveDelayMs = effectiveDelay,
            random = rnd,
            isFirstPacket = isFirstPacket
        )
        executor.executeTcp(tcpContext)"""

new_apply_tcp = """        val tcpContext = TcpExecutionContext(
            socket = socket,
            output = output,
            data = finalData,
            length = finalLen,
            host = host,
            strategy = strategy,
            config = config,
            effectiveDelayMs = effectiveDelay,
            random = rnd,
            isFirstPacket = isFirstPacket
        )
        try {
            executor.executeTcp(tcpContext)
        } catch (e: Exception) {
            if (e is UnsupportedStrategyException) throw e
            if (e is java.net.ConnectException || e is java.net.NoRouteToHostException) {
                throw TransportException("Transport failed during TCP strategy", e)
            }
            val reason = if (e.message?.contains("reset", true) == true || e.message?.contains("broken pipe", true) == true) {
                FailureReason.TCP_RESET
            } else {
                FailureReason.CENSORSHIP_STALL
            }
            throw StrategyException("Strategy execution failed for $strategy: ${e.message}", reason, e)
        }"""

content = content.replace(old_apply_tcp, new_apply_tcp)

old_apply_udp = """        val udpContext = UdpExecutionContext(
            socket = socket,
            address = packet.address,
            port = packet.port,
            data = data,
            length = packet.length,
            host = host,
            strategy = strategy,
            config = config,
            random = rnd
        )
        executor.executeUdp(udpContext)"""

new_apply_udp = """        val udpContext = UdpExecutionContext(
            socket = socket,
            address = packet.address,
            port = packet.port,
            data = data,
            length = packet.length,
            host = host,
            strategy = strategy,
            config = config,
            random = rnd
        )
        try {
            executor.executeUdp(udpContext)
        } catch (e: Exception) {
            if (e is UnsupportedStrategyException) throw e
            if (e is java.net.PortUnreachableException || e is java.net.NoRouteToHostException) {
                throw TransportException("Transport failed during UDP strategy", e)
            }
            throw StrategyException("Strategy execution failed for $strategy: ${e.message}", FailureReason.CENSORSHIP_STALL, e)
        }"""

content = content.replace(old_apply_udp, new_apply_udp)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassApplier.kt", "w") as f:
    f.write(content)


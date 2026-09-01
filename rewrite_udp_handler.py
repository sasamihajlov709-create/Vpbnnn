import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "r") as f:
    content = f.read()

# Replace activeSessions and pendingUdpProbes
content = content.replace("        val activeSessions = ConcurrentHashMap<UdpSessionKey, SessionState>()\n", "")
content = content.replace("        data class UdpPendingProbe(val host: String, val strategy: BypassStrategy, val sentTime: Long)\n", "")
content = content.replace("        val pendingUdpProbes = ConcurrentHashMap<UdpSessionKey, UdpPendingProbe>()\n", "")

# Replace state lookup and creation
old_state_lookup = """                                var state = activeSessions[sessionKey]
                                if (state == null) {
                                    var targetInet: InetAddress? = null
                                    val isIp = host.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) || host.contains(":")
                                    if (isIp) {
                                        targetInet = InetAddress.getByName(host)
                                    } else {
                                        val resolved = RobustResolver.resolveDual(host, vpnService)
                                        if (resolved.isNotEmpty()) {
                                            targetInet = resolved.random()
                                        }
                                    }
                                    
                                    if (targetInet == null) {
                                        Log.w("UdpTransport", "Failed to resolve $host")
                                        continue
                                    }
                                    val outSocket = UdpTransportManager.createProtectedSocket(vpnService)
                                    
                                    val readerJob = launch(ProxyDispatcher.udpRelay) {"""

new_state_lookup = """                                val udpStrat = DpiStrategySelector.getBestStrategy(HostClassifier.classify(host), host, TransportType.UDP)
                                var association = UdpAssociationTable.getSession(sessionKey)
                                if (association == null || association.outSocket == null) {
                                    var targetInet: InetAddress? = null
                                    val isIp = host.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) || host.contains(":")
                                    if (isIp) {
                                        targetInet = InetAddress.getByName(host)
                                    } else {
                                        val resolved = RobustResolver.resolveDual(host, vpnService)
                                        if (resolved.isNotEmpty()) {
                                            targetInet = resolved.random()
                                        }
                                    }
                                    
                                    if (targetInet == null) {
                                        Log.w("UdpTransport", "Failed to resolve $host")
                                        continue
                                    }
                                    association = UdpAssociationTable.getOrCreateSession(clientAddr, clientPort, host, port, udpStrat)
                                    val outSocket = UdpTransportManager.createProtectedSocket(vpnService)
                                    association.outSocket = outSocket
                                    association.targetInet = targetInet
                                    
                                    val readerJob = launch(ProxyDispatcher.udpRelay) {"""

content = content.replace(old_state_lookup, new_state_lookup)

old_reader = """                                                val matchedProbe = pendingUdpProbes.remove(sessionKey)
                                                if (matchedProbe != null) {"""
new_reader = """                                                val matchedProbe = UdpAssociationTable.getSession(sessionKey)?.popProbe()
                                                if (matchedProbe != null) {"""
content = content.replace(old_reader, new_reader)

old_state_save = """                                    }
                                    
                                    state = SessionState(outSocket, targetInet, readerJob)
                                    activeSessions[sessionKey] = state
                                }
                                val udpStrat = DpiStrategySelector.getBestStrategy(HostClassifier.classify(host), host, TransportType.UDP)
                                val sessionEntry = UdpAssociationTable.getOrCreateSession(clientAddr, clientPort, host, port, udpStrat)
                                if (udpStrat != BypassStrategy.DIRECT && udpStrat.implementationStatus != ImplementationStatus.UNSUPPORTED && udpStrat.implementationStatus != ImplementationStatus.SIMULATED) {
                                    pendingUdpProbes[sessionKey] = UdpPendingProbe(host, udpStrat, System.currentTimeMillis())
                                    launch(ProxyDispatcher.udpRelay) {
                                        try {
                                            UdpAssociationTable.touchSession(sessionKey, sentBytes = payload.size.toLong())
                                            val config = BypassConfig.getSessionConfig(host, udpStrat, 50, TransportType.UDP)
                                            val outPacket = DatagramPacket(payload, payload.size, state.targetInet, port)
                                            BypassApplier.applyUdpBypass(state.outSocket, outPacket, config, host)"""

new_state_save = """                                    }
                                    
                                    association.readerJob = readerJob
                                }
                                
                                if (udpStrat != BypassStrategy.DIRECT && udpStrat.implementationStatus != ImplementationStatus.UNSUPPORTED && udpStrat.implementationStatus != ImplementationStatus.SIMULATED) {
                                    association.addProbe(UdpPendingProbe(host, udpStrat, System.currentTimeMillis()))
                                    launch(ProxyDispatcher.udpRelay) {
                                        try {
                                            UdpAssociationTable.touchSession(sessionKey, sentBytes = payload.size.toLong())
                                            val config = BypassConfig.getSessionConfig(host, udpStrat, 50, TransportType.UDP)
                                            val outPacket = DatagramPacket(payload, payload.size, association.targetInet, port)
                                            BypassApplier.applyUdpBypass(association.outSocket!!, outPacket, config, host)"""
content = content.replace(old_state_save, new_state_save)

old_probe_remove = """                                            pendingUdpProbes.remove(sessionKey)"""
new_probe_remove = """                                            UdpAssociationTable.getSession(sessionKey)?.popProbe()"""
content = content.replace(old_probe_remove, new_probe_remove)

old_fallback = """                                } else {
                                    UdpAssociationTable.touchSession(sessionKey, sentBytes = payload.size.toLong())
                                    state.outSocket.send(DatagramPacket(payload, payload.size, state.targetInet, port))
                                    ProxyStats.recordStats("udp_outbound", 0, payload.size.toLong())
                                }"""
new_fallback = """                                } else {
                                    UdpAssociationTable.touchSession(sessionKey, sentBytes = payload.size.toLong())
                                    association.outSocket?.send(DatagramPacket(payload, payload.size, association.targetInet, port))
                                    ProxyStats.recordStats("udp_outbound", 0, payload.size.toLong())
                                }"""
content = content.replace(old_fallback, new_fallback)

old_finally = """        } finally {
            try { udpSocket.close() } catch(e:Exception){}
            activeSessions.values.forEach { 
                it.readerJob.cancel()
                try { it.outSocket.close() } catch (e: Exception) {} 
            }
            try { clientSocket.close() } catch (e: Exception) {}
        }"""
new_finally = """        } finally {
            try { udpSocket.close() } catch(e:Exception){}
            UdpAssociationTable.clear()
            try { clientSocket.close() } catch (e: Exception) {}
        }"""
content = content.replace(old_finally, new_finally)

content = content.replace("    data class SessionState(\n        val outSocket: DatagramSocket,\n        val targetInet: InetAddress,\n        val readerJob: Job\n    )\n\n", "")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "w") as f:
    f.write(content)

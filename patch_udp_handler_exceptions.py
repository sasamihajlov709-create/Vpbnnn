import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "r") as f:
    content = f.read()

old_catch = """                                        } catch (e: Exception) {
                                            if (e !is CancellationException) Log.v("UdpTransport", "UDP Strategy execution failed: ${e.message}")
                                            association.popProbe()
                                            DpiStrategySelector.recordResult(
                                                strategy = udpStrat,
                                                success = false,
                                                transport = TransportType.UDP,
                                                latencyMs = 5000L,
                                                host = host,
                                                quality = ObservationQuality.CONNECT_ONLY,
                                                requestedStrategy = udpStrat,
                                                effectiveStrategy = udpStrat
                                            )
                                        }"""

new_catch = """                                        } catch (e: Exception) {
                                            if (e !is CancellationException) Log.v("UdpTransport", "UDP Strategy execution failed: ${e.message}")
                                            association.popProbe()
                                            if (e !is TransportException && e !is DnsException && e !is java.net.UnknownHostException) {
                                                DpiStrategySelector.recordResult(
                                                    strategy = udpStrat,
                                                    success = false,
                                                    transport = TransportType.UDP,
                                                    latencyMs = 5000L,
                                                    host = host,
                                                    quality = ObservationQuality.CONNECT_ONLY,
                                                    requestedStrategy = udpStrat,
                                                    effectiveStrategy = udpStrat
                                                )
                                            }
                                        }"""

content = content.replace(old_catch, new_catch)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "w") as f:
    f.write(content)


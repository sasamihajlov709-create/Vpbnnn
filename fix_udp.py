with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "r") as f:
    content = f.read()
    
# Fix the mangled recordResult call
bad_str = "DpiStrategySelector.recordResult(strategy = matchedProbe.strategy, success = true, transport = TransportType.UDP, latencyMs = latency, host = matchedProbe.host, quality = ObservationQuality.APPLICATION_DATA_EXCHANGED, requestedStrategy = matchedProbe.strategy, effectiveStrategy = matchedProbe.strategyhost, udpStrat, false, 5000L, ObservationQuality.NO_REPLY, udpStrat, udpStrat, TransportType.UDP)"
good_str = "DpiStrategySelector.recordResult(strategy = udpStrat, success = false, transport = TransportType.UDP, latencyMs = 5000L, host = host, quality = ObservationQuality.NO_REPLY, requestedStrategy = udpStrat, effectiveStrategy = udpStrat)"

content = content.replace(bad_str, good_str)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "w") as f:
    f.write(content)

sed -i '80,117c\
        val currentProfileId = NetworkProfileManager.currentProfile.value.id\
        StrategyStateRepository.cleanupExpired(currentProfileId)\
\
        if (StrategyStateRepository.consecutiveFailuresByHost.size > 500) {\
            StrategyStateRepository.consecutiveFailuresByHost.entries.removeIf { it.value.get() == 0 }\
            if (StrategyStateRepository.consecutiveFailuresByHost.size > 1000) StrategyStateRepository.consecutiveFailuresByHost.clear()\
        }\
\
        val tcpStates = StrategyStateRepository.getAllContextStates().filterKeys { it.transport == TransportType.TCP && it.profileId == currentProfileId }.values\
        val udpStates = StrategyStateRepository.getAllContextStates().filterKeys { it.transport == TransportType.UDP && it.profileId == currentProfileId }.values\
        val dnsStates = StrategyStateRepository.getAllContextStates().filterKeys { it.transport == TransportType.DNS && it.profileId == currentProfileId }.values\
\
        val tcpSuccess = tcpStates.sumOf { it.successCount.get() }\
        val tcpFailure = tcpStates.sumOf { it.failureCount.get() }\
        val udpSuccess = udpStates.sumOf { it.successCount.get() }\
        val udpFailure = udpStates.sumOf { it.failureCount.get() }\
        val dnsSuccess = dnsStates.sumOf { it.successCount.get() }\
        val dnsFailure = dnsStates.sumOf { it.failureCount.get() }\
' app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt

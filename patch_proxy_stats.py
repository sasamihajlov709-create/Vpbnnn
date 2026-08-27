import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StabilityAnalyzer.kt", "r") as f:
    content = f.read()

replacement = """
    private val _tcpCensorshipIntensity = MutableStateFlow(0)
    val tcpCensorshipIntensity: StateFlow<Int> = _tcpCensorshipIntensity.asStateFlow()
    
    private val _udpCensorshipIntensity = MutableStateFlow(0)
    val udpCensorshipIntensity: StateFlow<Int> = _udpCensorshipIntensity.asStateFlow()
    
    private val _dnsCensorshipIntensity = MutableStateFlow(0)
    val dnsCensorshipIntensity: StateFlow<Int> = _dnsCensorshipIntensity.asStateFlow()
    
    private val _censorshipIntensity = MutableStateFlow(0)
"""
content = re.sub(r'    private val _censorshipIntensity = MutableStateFlow\(0\)', replacement.lstrip('\n'), content)

replacement_funcs = """
    fun setCensorshipIntensity(newVal: Int) {
        _censorshipIntensity.value = newVal.coerceIn(0, 100)
    }
    
    fun setTcpCensorshipIntensity(newVal: Int) {
        _tcpCensorshipIntensity.value = newVal.coerceIn(0, 100)
    }
    
    fun setUdpCensorshipIntensity(newVal: Int) {
        _udpCensorshipIntensity.value = newVal.coerceIn(0, 100)
    }
    
    fun setDnsCensorshipIntensity(newVal: Int) {
        _dnsCensorshipIntensity.value = newVal.coerceIn(0, 100)
    }
"""
content = re.sub(r'    fun setCensorshipIntensity\(value: Int\) \{\n        _censorshipIntensity\.value = value\.coerceIn\(0, 100\)\n    \}', replacement_funcs.lstrip('\n'), content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/StabilityAnalyzer.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyStats.kt", "r") as f:
    content = f.read()

replacement_proxystats = """
    val censorshipIntensity = StabilityAnalyzer.censorshipIntensity
    val tcpCensorshipIntensity = StabilityAnalyzer.tcpCensorshipIntensity
    val udpCensorshipIntensity = StabilityAnalyzer.udpCensorshipIntensity
    val dnsCensorshipIntensity = StabilityAnalyzer.dnsCensorshipIntensity
    
    fun updateCensorshipIntensity(newVal: Int) { StabilityAnalyzer.setCensorshipIntensity(newVal) }
    fun updateTcpCensorshipIntensity(newVal: Int) { StabilityAnalyzer.setTcpCensorshipIntensity(newVal) }
    fun updateUdpCensorshipIntensity(newVal: Int) { StabilityAnalyzer.setUdpCensorshipIntensity(newVal) }
    fun updateDnsCensorshipIntensity(newVal: Int) { StabilityAnalyzer.setDnsCensorshipIntensity(newVal) }
"""
content = re.sub(
    r'    val censorshipIntensity = StabilityAnalyzer\.censorshipIntensity\n    fun updateCensorshipIntensity\(newVal: Int\) \{ StabilityAnalyzer\.setCensorshipIntensity\(newVal\) \}',
    replacement_proxystats.lstrip('\n'),
    content
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyStats.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "r") as f:
    content = f.read()

replacement_engine = """
    fun aggregateGlobalMetrics() {
        val tcpIntensity = transportPolicies[TransportType.TCP]?.calculatedIntensity ?: 0
        val udpIntensity = transportPolicies[TransportType.UDP]?.calculatedIntensity ?: 0
        val dnsIntensity = transportPolicies[TransportType.DNS]?.calculatedIntensity ?: 0
        
        ProxyStats.updateTcpCensorshipIntensity(tcpIntensity)
        ProxyStats.updateUdpCensorshipIntensity(udpIntensity)
        ProxyStats.updateDnsCensorshipIntensity(dnsIntensity)
                
        // Aggregate censorship intensity (weighted towards TCP as the most common protocol)
        val globalIntensity = (tcpIntensity * 0.5 + udpIntensity * 0.3 + dnsIntensity * 0.2).toInt()
                
        if (Math.abs(globalIntensity - ProxyStats.censorshipIntensity.value) >= 1) {
            ProxyStats.updateCensorshipIntensity(globalIntensity)
        }
    }
"""
content = re.sub(r'    fun aggregateGlobalMetrics\(\) \{.*?(?=    fun resetProfileEngineStates)', replacement_engine.lstrip('\n'), content, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt", "w") as f:
    f.write(content)


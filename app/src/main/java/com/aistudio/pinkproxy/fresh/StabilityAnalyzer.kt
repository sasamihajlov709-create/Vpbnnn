package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.flow.*

object StabilityAnalyzer {
    private val _lastLatency = MutableStateFlow(0L)
    val lastLatency: StateFlow<Long> = _lastLatency.asStateFlow()

    private val _jitter = MutableStateFlow(0L)
    val jitter: StateFlow<Long> = _jitter.asStateFlow()

    private val _stabilityScore = MutableStateFlow(100)
    val stabilityScore: StateFlow<Int> = _stabilityScore.asStateFlow()

    private val _successRate = MutableStateFlow(100)
    val successRate: StateFlow<Int> = _successRate.asStateFlow()

    private val _tcpSuccessRate = MutableStateFlow(100)
    val tcpSuccessRate: StateFlow<Int> = _tcpSuccessRate.asStateFlow()

    private val _udpSuccessRate = MutableStateFlow(100)
    val udpSuccessRate: StateFlow<Int> = _udpSuccessRate.asStateFlow()

    private val _dnsSuccessRate = MutableStateFlow(100)
    val dnsSuccessRate: StateFlow<Int> = _dnsSuccessRate.asStateFlow()

    private val _tcpCensorshipIntensity = MutableStateFlow(0)
    val tcpCensorshipIntensity: StateFlow<Int> = _tcpCensorshipIntensity.asStateFlow()
    
    private val _udpCensorshipIntensity = MutableStateFlow(0)
    val udpCensorshipIntensity: StateFlow<Int> = _udpCensorshipIntensity.asStateFlow()
    
    private val _dnsCensorshipIntensity = MutableStateFlow(0)
    val dnsCensorshipIntensity: StateFlow<Int> = _dnsCensorshipIntensity.asStateFlow()
    
    private val _censorshipIntensity = MutableStateFlow(0)

    val censorshipIntensity: StateFlow<Int> = _censorshipIntensity.asStateFlow()

    private val _dpiEventHistory = MutableStateFlow(emptyList<DpiEvent>())
    val dpiEventHistory: StateFlow<List<DpiEvent>> = _dpiEventHistory.asStateFlow()

    private val _currentDpiType = MutableStateFlow(DpiType.NONE)
    val currentDpiType: StateFlow<DpiType> = _currentDpiType.asStateFlow()

    private val _signalQuality = MutableStateFlow(100)
    val signalQuality: StateFlow<Int> = _signalQuality.asStateFlow()

    fun updateLatency(ms: Long) {
        val old = _lastLatency.value
        if (old > 0) {
            val diff = Math.abs(ms - old)
            _jitter.value = (_jitter.value * 3 + diff) / 4
        }
        _lastLatency.value = ms
    }

    fun recordEvent(isFailure: Boolean, rtt: Long = 0, transport: TransportType) {
        if (isFailure) {
            _successRate.update { (it * 0.85 + 0).toInt().coerceIn(0, 100) }
            when (transport) {
                TransportType.TCP -> _tcpSuccessRate.update { (it * 0.85 + 0).toInt().coerceIn(0, 100) }
                TransportType.UDP -> _udpSuccessRate.update { (it * 0.85 + 0).toInt().coerceIn(0, 100) }
                TransportType.DNS -> _dnsSuccessRate.update { (it * 0.85 + 0).toInt().coerceIn(0, 100) }
            }
            _censorshipIntensity.update { (it + 8).coerceAtMost(100) }
            _stabilityScore.update { (it - 3).coerceAtLeast(0) }
        } else {
            _successRate.update { (it * 0.98 + 2).toInt().coerceIn(0, 100) }
            when (transport) {
                TransportType.TCP -> _tcpSuccessRate.update { (it * 0.98 + 2).toInt().coerceIn(0, 100) }
                TransportType.UDP -> _udpSuccessRate.update { (it * 0.98 + 2).toInt().coerceIn(0, 100) }
                TransportType.DNS -> _dnsSuccessRate.update { (it * 0.98 + 2).toInt().coerceIn(0, 100) }
            }
            _censorshipIntensity.update { (it - 2).coerceAtLeast(0) }
            if (rtt > 0) {
                val lastRtt = _lastLatency.value
                val jitterValue = Math.abs(rtt - lastRtt)
                val jitterPenalty = (jitterValue / 10).coerceAtMost(30)
                _stabilityScore.update { (it * 0.95 + (100 - jitterPenalty) * 0.05).toInt().coerceIn(0, 100) }
                updateLatency(rtt)
            }
        }
    }

    fun recordDpi(type: DpiType) {
        _currentDpiType.value = type
        _dpiEventHistory.update { current ->
            (current + DpiEvent(type)).takeLast(50)
        }
    }

    fun updateSignalQuality(successRate: Int, stabilityScore: Int, censorshipIntensity: Int, isPanicMode: Boolean) {
        val baseQual = successRate.coerceIn(0, 100)
        val stabPenalty = (100 - stabilityScore) / 2
        val panicPenalty = if (isPanicMode) 15 else 0
        val intensityPenalty = (censorshipIntensity / 10).coerceAtMost(10)
        
        _signalQuality.value = (baseQual - stabPenalty - panicPenalty - intensityPenalty).coerceIn(0, 100)
    }

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


    fun setStabilityScore(value: Int) {
        _stabilityScore.value = value.coerceIn(0, 100)
    }

    fun reset() {
        _lastLatency.value = 0
        _jitter.value = 0
        _stabilityScore.value = 100
        _successRate.value = 100
        _tcpSuccessRate.value = 100
        _udpSuccessRate.value = 100
        _dnsSuccessRate.value = 100
        _censorshipIntensity.value = 0
        _currentDpiType.value = DpiType.NONE
        _dpiEventHistory.value = emptyList()
        _signalQuality.value = 100
    }
}

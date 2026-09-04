package com.aistudio.pinkproxy.fresh

data class SessionConfig(
    val strategy: BypassStrategy,
    val requestedStrategy: BypassStrategy = strategy,
    val frag1: Int,
    val delay1: Long,
    val fakeTtl: Int,
    val useIPv6: Boolean = false,
    val frag2: Int = 0,
    val frag3: Int = 0,
    val delay2: Long = 0,
    val mss: Int = 1300,
    val selectionContext: CandidateEngine.SelectionContext? = null
)

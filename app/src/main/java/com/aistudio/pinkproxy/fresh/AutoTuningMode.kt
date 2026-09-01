package com.aistudio.pinkproxy.fresh

enum class AutoTuningMode {
    /**
     * Production stable mode: only strategies verified on real devices or confirmed with high confidence.
     */
    STABLE,

    /**
     * Adaptive exploration mode: samples all implemented strategies with calibrated Bayesian exploration.
     */
    EXPLORATION,

    /**
     * Diagnostics mode: runs specific strategy tests without automated promotion.
     */
    DIAGNOSTIC
}

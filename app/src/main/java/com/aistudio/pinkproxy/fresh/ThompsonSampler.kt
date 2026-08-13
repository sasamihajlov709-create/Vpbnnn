package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ThreadLocalRandom
import kotlin.math.ln
import kotlin.math.sqrt

/**
 * High-performance Bayesian Multi-Armed Bandit using Thompson Sampling with Beta Distributions.
 * Mathematically balances exploration of new bypass methods and exploitation of proven ones.
 */
object ThompsonSampler {

    /**
     * Samples from a Beta(alpha, beta) distribution using standard gamma transforms (Marsaglia and Tsang method).
     * @param alpha Successes + prior (alpha > 0)
     * @param beta Failures + prior (beta > 0)
     */
    fun sampleBeta(alpha: Double, beta: Double): Double {
        val a = alpha.coerceAtLeast(0.1)
        val b = beta.coerceAtLeast(0.1)

        val gammaA = sampleGamma(a)
        val gammaB = sampleGamma(b)

        val sum = gammaA + gammaB
        return if (sum <= 0.0) 0.5 else (gammaA / sum).coerceIn(0.0001, 0.9999)
    }

    private fun sampleGamma(shape: Double): Double {
        val rnd = ThreadLocalRandom.current()
        if (shape < 1.0) {
            val u = rnd.nextDouble()
            return sampleGamma(shape + 1.0) * Math.pow(u, 1.0 / shape)
        }

        val d = shape - 1.0 / 3.0
        val c = 1.0 / sqrt(9.0 * d)

        while (true) {
            var v: Double
            var x: Double
            do {
                x = rnd.nextGaussian()
                v = 1.0 + c * x
            } while (v <= 0.0)

            v = v * v * v
            val u = rnd.nextDouble()

            if (u < 1.0 - 0.0331 * x * x * x * x) {
                return d * v
            }

            if (ln(u) < 0.5 * x * x + d * (1.0 - v + ln(v))) {
                return d * v
            }
        }
    }
}

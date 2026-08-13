package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.delay
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom

/**
 * Zapret-grade Multi-Stage Composite Evasion Pipeline.
 * Chains together fake decoy injection, multi-level TLS record splitting, and TCP window modulation.
 */
object CompositePipelineApplier {

    suspend fun applyZapretTriplePipeline(
        socket: Socket,
        output: OutputStream,
        data: ByteArray,
        length: Int,
        host: String,
        config: SessionConfig,
        rnd: ThreadLocalRandom
    ) {
        if (!TlsParser.isClientHello(data, length)) {
            output.write(data, 0, length)
            output.flush()
            return
        }

        val sniPos = TlsParser.findSni(data, length)
        val splitPos = if (sniPos > 5) sniPos else (length / 2).coerceIn(2, length - 2)
        val fakeTtl = config.fakeTtl.takeIf { it > 0 } ?: StrategyUtils.getFakeTtl(host, rnd)

        // Stage 1: TCP Window Shrinking (Stall TSPU packet reassembly window)
        try {
            socket.receiveBufferSize = 1
        } catch (e: Exception) {}

        // Stage 2: Send fake ClientHello with tuned TTL (expires at middlebox)
        val decoyDomain = if (rnd.nextBoolean()) "google.com" else "cloudflare.com"
        val fakeHello = FakePacketHelper.buildRealisticTlsHello(decoyDomain)
        TtlHelper.setTtl(socket, fakeTtl)
        output.write(fakeHello)
        output.flush()
        delay(rnd.nextLong(1, 3))

        // Stage 3: Split TLS Record at SNI boundary and transmit real payload with system TTL
        TtlHelper.setTtl(socket, BypassConfig.currentTtl)
        
        // Chunk 1: Header up to SNI
        output.write(data, 0, splitPos)
        output.flush()
        delay(config.delay1.coerceIn(1L, 10L))

        // Stage 4: Restore TCP Window Buffer
        try {
            socket.receiveBufferSize = 65536
        } catch (e: Exception) {}

        // Chunk 2: Remainder of ClientHello
        output.write(data, splitPos, length - splitPos)
        output.flush()
    }
}

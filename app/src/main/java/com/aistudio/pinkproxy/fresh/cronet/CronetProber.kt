package com.aistudio.pinkproxy.fresh.cronet

import kotlinx.coroutines.suspendCancellableCoroutine
import org.chromium.net.CronetEngine
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import org.chromium.net.CronetException
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object CronetProber {
    private val executor = Executors.newSingleThreadExecutor()

    /**
     * Probes an endpoint to see if HTTP/3 (QUIC) is viable.
     * Returns true if the handshake succeeds and protocol negotiated is QUIC/H3.
     */
    suspend fun probeQuic(url: String): Boolean = withContext(Dispatchers.IO) {
        val engine = CronetEngineProvider.getEngine() ?: return@withContext false

        return@withContext try {
            suspendCancellableCoroutine { continuation ->
                val callback = object : UrlRequest.Callback() {
                    override fun onRedirectReceived(request: UrlRequest, info: UrlResponseInfo, newLocationUrl: String) {
                        request.followRedirect()
                    }

                    override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                        val wasQuic = info.negotiatedProtocol.startsWith("h3") || info.negotiatedProtocol.startsWith("quic")
                        request.cancel() // We just need to know it started
                        if (!continuation.isCompleted) {
                            continuation.resume(wasQuic)
                        }
                    }

                    override fun onReadCompleted(request: UrlRequest, info: UrlResponseInfo, byteBuffer: ByteBuffer) {}

                    override fun onSucceeded(request: UrlRequest, info: UrlResponseInfo) {
                        // Already handled in onResponseStarted
                    }

                    override fun onFailed(request: UrlRequest, info: UrlResponseInfo?, error: CronetException) {
                        if (!continuation.isCompleted) {
                            continuation.resume(false)
                        }
                    }

                    override fun onCanceled(request: UrlRequest, info: UrlResponseInfo?) {
                        // Canceled normally means we canceled it in onResponseStarted, 
                        // so it should already be completed.
                        if (!continuation.isCompleted) {
                            continuation.resume(false)
                        }
                    }
                }

                val request = engine.newUrlRequestBuilder(url, callback, executor)
                    .setHttpMethod("HEAD")
                    .build()

                continuation.invokeOnCancellation {
                    request.cancel()
                }

                request.start()
            }
        } catch (e: Exception) {
            false
        }
    }
}

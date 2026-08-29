package com.aistudio.pinkproxy.fresh.cronet

import android.util.Log
import kotlinx.coroutines.suspendCancellableCoroutine
import org.chromium.net.CronetEngine
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import org.chromium.net.CronetException
import java.nio.ByteBuffer
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class CronetDohTransport(private val engine: CronetEngine) {
    
    suspend fun resolveDoH(url: String, dnsWireFormat: ByteArray): ByteArray? {
        val executor = CronetEngineProvider.getExecutor()
        CronetMetrics.recordAttempt()
        
        return suspendCancellableCoroutine { continuation ->
            val callback = object : UrlRequest.Callback() {
                private val responseData = mutableListOf<ByteBuffer>()
                private var wasQuic = false
                private val startTime = System.currentTimeMillis()

                override fun onRedirectReceived(request: UrlRequest, info: UrlResponseInfo, newLocationUrl: String) {
                    Log.w("CronetDohTransport", "DNS redirect blocked for security: $url -> $newLocationUrl")
                    request.cancel()
                }

                override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                    wasQuic = info.negotiatedProtocol.startsWith("h3") || info.negotiatedProtocol.startsWith("quic")
                    // Metrics accounting moved to onSucceeded to reflect true business-level completion
                    val buffer = ByteBuffer.allocateDirect(1024)
                    request.read(buffer)
                }

                override fun onReadCompleted(request: UrlRequest, info: UrlResponseInfo, byteBuffer: ByteBuffer) {
                    byteBuffer.flip()
                    responseData.add(byteBuffer)
                    val nextBuffer = ByteBuffer.allocateDirect(1024)
                    request.read(nextBuffer)
                }

                override fun onSucceeded(request: UrlRequest, info: UrlResponseInfo) {
                    val size = responseData.sumOf { it.remaining() }
                    val result = ByteArray(size)
                    var offset = 0
                    for (buffer in responseData) {
                        val remaining = buffer.remaining()
                        buffer.get(result, offset, remaining)
                        offset += remaining
                    }
                    
                    val latencyMs = System.currentTimeMillis() - startTime
                    if (wasQuic) {
                        CronetMetrics.recordQuicHandshake()
                    }
                    CronetMetrics.recordSuccess(latencyMs, wasQuic)
                    
                    continuation.resume(result)
                }

                override fun onFailed(request: UrlRequest, info: UrlResponseInfo?, error: CronetException) {
                    Log.e("CronetDohTransport", "DoH Request Failed", error)
                    if (error.cause?.message?.contains("timeout") == true) {
                        CronetMetrics.recordTimeout()
                    }
                    continuation.resumeWithException(error)
                }

                override fun onCanceled(request: UrlRequest, info: UrlResponseInfo?) {
                    continuation.resume(null)
                }
            }

            val requestBuilder = engine.newUrlRequestBuilder(url, callback, executor)
                .setHttpMethod("POST")
                .addHeader("Content-Type", "application/dns-message")
                .addHeader("Accept", "application/dns-message")

            // Create UploadDataProvider for the dns wire format
            val uploadDataProvider = object : org.chromium.net.UploadDataProvider() {
                private var offset = 0
                
                override fun getLength(): Long = dnsWireFormat.size.toLong()
                
                override fun read(uploadDataSink: org.chromium.net.UploadDataSink, byteBuffer: ByteBuffer) {
                    val remaining = dnsWireFormat.size - offset
                    if (remaining > 0) {
                        val len = minOf(byteBuffer.remaining(), remaining)
                        byteBuffer.put(dnsWireFormat, offset, len)
                        offset += len
                    }
                    uploadDataSink.onReadSucceeded(false)
                }

                override fun rewind(uploadDataSink: org.chromium.net.UploadDataSink) {
                    offset = 0
                    uploadDataSink.onRewindSucceeded()
                }
            }
            
            requestBuilder.setUploadDataProvider(uploadDataProvider, executor)
            val request = requestBuilder.build()
            
            continuation.invokeOnCancellation {
                request.cancel()
            }
            
            request.start()
        }
    }
}

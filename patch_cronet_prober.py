import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/cronet/CronetProber.kt", "r") as f:
    content = f.read()

content = content.replace("suspend fun probeQuic(url: String)", "suspend fun probeHttp3Negotiation(url: String)")

old_callback = """                    override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                        val wasQuic = info.negotiatedProtocol.startsWith("h3") || info.negotiatedProtocol.startsWith("quic")
                        request.cancel() // We just need to know it started
                        if (!continuation.isCompleted) {
                            continuation.resume(wasQuic)
                        }
                    }"""

new_callback = """                    override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                        val wasQuic = info.negotiatedProtocol.startsWith("h3") || info.negotiatedProtocol.startsWith("quic")
                        if (!continuation.isCompleted) {
                            continuation.resume(wasQuic)
                        }
                        try { request.cancel() } catch(e:Exception){}
                    }"""

content = content.replace(old_callback, new_callback)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/cronet/CronetProber.kt", "w") as f:
    f.write(content)


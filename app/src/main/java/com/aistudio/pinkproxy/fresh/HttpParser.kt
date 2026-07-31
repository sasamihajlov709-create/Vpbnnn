package com.aistudio.pinkproxy.fresh

object HttpParser {
    private val HTTP_METHODS = setOf("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH", "TRACE")

    private val HTTP2_PREAMBLE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()

    fun isHttp2Preamble(data: ByteArray, length: Int): Boolean {
        if (length < HTTP2_PREAMBLE.size) return false
        for (i in HTTP2_PREAMBLE.indices) {
            if (data[i] != HTTP2_PREAMBLE[i]) return false
        }
        return true
    }

    fun isHttpRequest(data: ByteArray, length: Int): Boolean {
        if (isHttp2Preamble(data, length)) return true
        if (length < 8) return false
        val s = String(data, 0, minOf(length, 10), Charsets.US_ASCII)
        val spaceIdx = s.indexOf(' ')
        if (spaceIdx == -1) return false
        val method = s.substring(0, spaceIdx)
        return HTTP_METHODS.contains(method.uppercase())
    }

    fun findHostOffset(data: ByteArray, length: Int): Int {
        val s = String(data, 0, length, Charsets.US_ASCII)
        val hostLine = s.lines().find { it.startsWith("Host:", true) } ?: return -1
        return s.indexOf(hostLine)
    }
}

package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ThreadLocalRandom

object HttpPacketBuilder {

    fun buildFakeHttpRequest(host: String): ByteArray {
        val paths = listOf("/", "/index.html", "/favicon.ico", "/api/v1/status", "/news")
        val path = paths.random()
        val agents = listOf(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        )
        val ua = agents.random()
        val request = "GET $path HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "User-Agent: $ua\r\n" +
                "Accept: */*\r\n" +
                "Connection: keep-alive\r\n\r\n"
        return request.toByteArray(Charsets.US_ASCII)
    }

    fun buildRealisticHttp2Header(): ByteArray {
        // Simple HTTP/2 connection preface + settings frame
        val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()
        val settings = byteArrayOf(0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)
        return preface + settings
    }

    fun buildHttpChaosPacket(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val methods = listOf("GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH")
        val method = methods.random()
        val headers = listOf("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP")
        val header = headers.random()
        val value = "${rnd.nextInt(1, 255)}.${rnd.nextInt(1, 255)}.${rnd.nextInt(1, 255)}.${rnd.nextInt(1, 255)}"
        val request = "$method /${rnd.nextInt(1000)} HTTP/1.1\r\n$header: $value\r\n\r\n"
        return request.toByteArray()
    }
}

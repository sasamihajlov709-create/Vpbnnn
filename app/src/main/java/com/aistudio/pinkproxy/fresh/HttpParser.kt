package com.aistudio.pinkproxy.fresh

object HttpParser {
    private val HTTP_METHODS = setOf("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH", "TRACE")

    private val HTTP2_PREAMBLE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray()

    fun isHttp2Preamble(data: ByteArray, length: Int): Boolean {
        if (length < HTTP2_PREAMBLE.size || length > data.size) return false
        for (i in HTTP2_PREAMBLE.indices) {
            if (data[i] != HTTP2_PREAMBLE[i]) return false
        }
        return true
    }

    fun isHttpRequest(data: ByteArray, length: Int): Boolean {
        if (length > data.size) return false
        if (length < 8) return false
        if (isHttp2Preamble(data, length)) return true

        val b0 = data[0].toInt().toChar()
        if (b0 == 'G') return data[1] == 'E'.code.toByte() && data[2] == 'T'.code.toByte() && data[3] == ' '.code.toByte()
        if (b0 == 'P') {
            if (data[1] == 'O'.code.toByte() && data[2] == 'S'.code.toByte() && data[3] == 'T'.code.toByte() && data[4] == ' '.code.toByte()) return true
            if (data[1] == 'U'.code.toByte() && data[2] == 'T'.code.toByte() && data[3] == ' '.code.toByte()) return true
            if (data[1] == 'A'.code.toByte() && data[2] == 'T'.code.toByte() && data[3] == 'C'.code.toByte() && data[4] == 'H'.code.toByte() && data[5] == ' '.code.toByte()) return true
        }
        if (b0 == 'H') return data[1] == 'E'.code.toByte() && data[2] == 'A'.code.toByte() && data[3] == 'D'.code.toByte() && data[4] == ' '.code.toByte()
        if (b0 == 'D') return data[1] == 'E'.code.toByte() && data[2] == 'L'.code.toByte() && data[3] == 'E'.code.toByte() && data[4] == 'T'.code.toByte() && data[5] == 'E'.code.toByte() && data[6] == ' '.code.toByte()
        if (b0 == 'O') return data[1] == 'P'.code.toByte() && data[2] == 'T'.code.toByte() && data[3] == 'I'.code.toByte() && data[4] == 'O'.code.toByte() && data[5] == 'N'.code.toByte() && data[6] == 'S'.code.toByte() && data[7] == ' '.code.toByte()
        if (b0 == 'C') return data[1] == 'O'.code.toByte() && data[2] == 'N'.code.toByte() && data[3] == 'N'.code.toByte() && data[4] == 'E'.code.toByte() && data[5] == 'C'.code.toByte() && data[6] == 'T'.code.toByte() && data[7] == ' '.code.toByte()
        if (b0 == 'T') return data[1] == 'R'.code.toByte() && data[2] == 'A'.code.toByte() && data[3] == 'C'.code.toByte() && data[4] == 'E'.code.toByte() && data[5] == ' '.code.toByte()

        return false
    }

    fun findHostOffset(data: ByteArray, length: Int): Int {
        if (length > data.size) return -1
        val s = String(data, 0, length, Charsets.US_ASCII)
        val hostLine = s.lines().find { it.startsWith("Host:", true) } ?: return -1
        return s.indexOf(hostLine)
    }

    fun mangleHostHeader(data: ByteArray, length: Int, mode: Int): ByteArray {
        if (length > data.size) return data
        val s = String(data, 0, length, Charsets.US_ASCII)
        val lines = s.split("\r\n").toMutableList()
        val hostIndex = lines.indexOfFirst { it.startsWith("Host:", true) }
        if (hostIndex == -1) return data

        val originalHostLine = lines[hostIndex]
        val hostValue = originalHostLine.substringAfter(":").trim()
        
        lines[hostIndex] = when (mode) {
            1 -> "hOsT: $hostValue" // Mixed case header name
            2 -> "Host:  $hostValue" // Double space
            3 -> "Host:\t$hostValue" // Tab instead of space
            4 -> "host: $hostValue" // Lowercase
            5 -> "HOST: $hostValue" // Uppercase
            6 -> "Host: $hostValue\r" // Trailing CR
            7 -> "Host: $hostValue " // Trailing space
            else -> originalHostLine
        }
        
        if (mode == 8) {
            lines.add(hostIndex, "X-Forwarded-Host: $hostValue")
        }
        
        return lines.joinToString("\r\n").toByteArray(Charsets.US_ASCII)
    }
}

package com.aistudio.pinkproxy.fresh

import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ThreadLocalRandom
import kotlinx.coroutines.delay

object StrategyHandlers {

    suspend fun handleHttpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        when (strategy) {
            BypassStrategy.HTTP_HEADER_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val mangled = HttpParser.mangleHostHeader(data, length, rnd.nextInt(1, 9))
                    output.write(mangled); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.HTTP_HOST_REVERSE -> {
                try {
                    val s = String(data, 0, length, Charsets.US_ASCII)
                    val lines = s.split("\r\n").toMutableList()
                    val hostIdx = lines.indexOfFirst { it.startsWith("Host:", ignoreCase = true) }
                    if (hostIdx != -1) {
                        val hostLine = lines[hostIdx]
                        val parts = hostLine.split(":")
                        if (parts.size >= 2) {
                            val key = parts[0].reversed()
                            lines[hostIdx] = "$key:${parts.drop(1).joinToString(":")}"
                        }
                    }
                    output.write(lines.joinToString("\r\n").toByteArray(Charsets.US_ASCII)); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_CHUNKED_FAKE -> {
                if (isProbableHttp(data, length)) {
                    try {
                        val chunkSize = rnd.nextInt(1, 16)
                        var p = 0
                        while (p < length) {
                            val nextLen = (length - p).coerceAtMost(chunkSize)
                            output.write(data, p, nextLen); output.flush()
                            p += nextLen
                            if (rnd.nextBoolean()) delay(1)
                        }
                    } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.HTTP_HOST_CASE_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd)
                        val modified = s.replace("Host:", "hOSt:", ignoreCase = true)
                        output.write(modified.toByteArray())
                        output.write(data, headerEnd, length - headerEnd)
                        output.flush()
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.HTTP_METHOD_SPACE_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val mod = FakePacketHelper.addSpaceToHttpMethod(data, length)
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_DOT_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val mod = FakePacketHelper.addDotToHost(data, length)
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_REORDER -> {
                if (!isProbableHttp(data, length)) {
                    output.write(data, 0, length); output.flush()
                } else {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd - 4, Charsets.US_ASCII)
                        val lines = s.split("\r\n").toMutableList()
                        val hostIdx = lines.indexOfFirst { it.startsWith("Host:", ignoreCase = true) }
                        if (hostIdx != -1 && lines.size > 1) {
                            val hostLine = lines.removeAt(hostIdx)
                            lines.add(1.coerceAtMost(lines.size), hostLine)
                            val newHead = lines.joinToString("\r\n") + "\r\n\r\n"
                            output.write(newHead.toByteArray(Charsets.US_ASCII))
                            output.write(data, headerEnd, length - headerEnd); output.flush()
                        } else { output.write(data, 0, length); output.flush() }
                    } else { output.write(data, 0, length); output.flush() }
                }
            }
            BypassStrategy.HTTP_HOST_MANGLE -> {
                var modified = false
                var newData: ByteArray? = null
                for (i in 0 until length - 4) {
                    if ((data[i] == 'H'.code.toByte() || data[i] == 'h'.code.toByte()) &&
                        (data[i+1] == 'o'.code.toByte() || data[i+1] == 'O'.code.toByte()) &&
                        (data[i+2] == 's'.code.toByte() || data[i+2] == 'S'.code.toByte()) &&
                        (data[i+3] == 't'.code.toByte() || data[i+3] == 'T'.code.toByte()) &&
                        data[i+4] == ':'.code.toByte()) {
                        newData = data.copyOf(length)
                        newData[i] = 'h'.code.toByte()
                        newData[i+1] = 'O'.code.toByte()
                        newData[i+2] = 's'.code.toByte()
                        newData[i+3] = 'T'.code.toByte()
                        modified = true; break
                    }
                }
                output.write(if (modified) newData!! else data, 0, length); output.flush()
            }
            BypassStrategy.HTTP_FRAGMENT -> {
                if (length > 20) {
                    val part = rnd.nextInt(5, 15)
                    output.write(data, 0, part); output.flush()
                    delay(rnd.nextLong(2, 8))
                    output.write(data, part, length - part); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_SMUGGLE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd - 4, Charsets.US_ASCII)
                        val lines = s.split("\r\n").toMutableList()
                        val hostIdx = lines.indexOfFirst { it.startsWith("Host:", ignoreCase = true) }
                        if (hostIdx != -1) {
                            lines.add(hostIdx, "Host: www.google.com")
                            val smuggled = lines.joinToString("\r\n") + "\r\n\r\n"
                            output.write(smuggled.toByteArray(Charsets.US_ASCII))
                            output.write(data, headerEnd, length - headerEnd); output.flush()
                        } else { output.write(data, 0, length); output.flush() }
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_USER_AGENT_SKEW -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val s = String(data, 0, headerEnd)
                        val modified = s.replace(Regex("User-Agent:.*?\r\n", RegexOption.IGNORE_CASE), "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n")
                        output.write(modified.toByteArray())
                        output.write(data, headerEnd, length - headerEnd); output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_RANGE_SKEW -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val firstLineEnd = String(data, 0, headerEnd).indexOf("\r\n")
                        if (firstLineEnd != -1) {
                            output.write(data, 0, firstLineEnd + 2)
                            output.write("Range: bytes=0-1\r\n".toByteArray())
                            output.write(data, firstLineEnd + 2, length - (firstLineEnd + 2)); output.flush()
                        } else { output.write(data, 0, length); output.flush() }
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_VERSION_SKEW -> {
                if (isProbableHttp(data, length)) {
                    val mod = data.copyOf(length)
                    for (i in 0 until length - 8) {
                        if (mod[i] == 'H'.code.toByte() && mod[i+1] == 'T'.code.toByte() && mod[i+2] == 'T'.code.toByte() && mod[i+3] == 'P'.code.toByte() && mod[i+4] == '/'.code.toByte() && mod[i+5] == '1'.code.toByte() && mod[i+6] == '.'.code.toByte() && mod[i+7] == '1'.code.toByte()) {
                            mod[i+7] = '0'.code.toByte()
                            break
                        }
                    }
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_METHOD_FAKE -> {
                if (isProbableHttp(data, length)) {
                    val fake = "POST / HTTP/1.1\r\nHost: $host\r\nContent-Length: 10\r\nConnection: keep-alive\r\n\r\nFAKE_DATA\r\n".toByteArray()
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    output.write(fake); output.flush()
                    delay(5)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, length); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_AUTH_RANDOM -> {
                if (isProbableHttp(data, length)) {
                    val header = "Authorization: Basic ${java.util.Base64.getEncoder().encodeToString(rnd.nextLong().toString().toByteArray())}\r\n".toByteArray()
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val firstLineEnd = String(data, 0, headerEnd).indexOf("\r\n")
                        if (firstLineEnd != -1) {
                            output.write(data, 0, firstLineEnd + 2)
                            output.write(header)
                            output.write(data, firstLineEnd + 2, length - (firstLineEnd + 2)); output.flush()
                        } else { output.write(data, 0, length); output.flush() }
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_SPACE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val head = data.copyOf(headerEnd)
                        var found = false
                        for (i in 0 until head.size - 6) {
                            if (head[i] == 'H'.code.toByte() && head[i+1] == 'o'.code.toByte() && head[i+4] == ':'.code.toByte() && head[i+5] == ' '.code.toByte()) {
                                 val newHead = ByteArray(head.size + 1)
                                 System.arraycopy(head, 0, newHead, 0, i + 6)
                                 newHead[i+6] = ' '.code.toByte()
                                 System.arraycopy(head, i + 6, newHead, i + 7, head.size - (i + 6))
                                 output.write(newHead)
                                 output.write(data, headerEnd, length - headerEnd); output.flush()
                                 found = true; break
                            }
                        }
                        if (!found) { output.write(data, 0, length); output.flush() }
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_LINE_SPLIT -> {
                try {
                    val s = String(data, 0, length, Charsets.US_ASCII)
                    val lines = s.split("\r\n")
                    if (lines.isNotEmpty() && (lines[0].startsWith("GET") || lines[0].startsWith("POST"))) {
                        val reqLine = lines[0]
                        if (reqLine.length > 5) {
                            val split = rnd.nextInt(1, 4)
                            output.write(reqLine.substring(0, split).toByteArray(Charsets.US_ASCII))
                            output.flush()
                            delay(rnd.nextLong(1, 5))
                            output.write(reqLine.substring(split).toByteArray(Charsets.US_ASCII))
                            output.write("\r\n".toByteArray(Charsets.US_ASCII))
                            output.flush()
                            
                            if (lines.size > 1) {
                                val rest = lines.drop(1).joinToString("\r\n")
                                output.write(rest.toByteArray(Charsets.US_ASCII))
                                output.flush()
                            }
                        } else { output.write(data, 0, length); output.flush() }
                    } else { output.write(data, 0, length); output.flush() }
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_METHOD_CASE_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val mod = FakePacketHelper.mangleHttpMethod(data, length)
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_TAB_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val head = String(data, 0, headerEnd, Charsets.US_ASCII)
                        val modified = head.replace("Host:", "Host:\t", ignoreCase = true)
                        output.write(modified.toByteArray(Charsets.US_ASCII))
                        output.write(data, headerEnd, length - headerEnd); output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_MULTI_LINE_MANGLE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val head = String(data, 0, headerEnd, Charsets.US_ASCII)
                        // Split into lines, fold only the headers, keep the first line (Request-Line) intact
                        val lines = head.split("\r\n")
                        if (lines.isNotEmpty()) {
                            val modified = StringBuilder(lines[0]).append("\r\n")
                            for (i in 1 until lines.size) {
                                if (lines[i].isNotEmpty()) {
                                    // Randomly fold some headers or mangle them
                                    if (rnd.nextBoolean()) {
                                        modified.append(lines[i].replaceFirst(":", ":\r\n "))
                                    } else {
                                        modified.append(lines[i])
                                    }
                                }
                                if (i < lines.size - 1) modified.append("\r\n")
                            }
                            output.write(modified.toString().toByteArray(Charsets.US_ASCII))
                            output.write(data, headerEnd, length - headerEnd); output.flush()
                        } else {
                            output.write(data, 0, length); output.flush()
                        }
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_HOST_FOLDING -> {
                if (isProbableHttp(data, length)) {
                    val headEnd = findHeaderEnd(data, length)
                    if (headEnd != -1) {
                        val head = String(data, 0, headEnd, Charsets.US_ASCII)
                        val modified = head.replace("Host:", "Host:\r\n ", ignoreCase = true)
                        output.write(modified.toByteArray(Charsets.US_ASCII))
                        output.write(data, headEnd, length - headEnd); output.flush()
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.HTTP_KEEP_ALIVE_FAKE -> {
                if (isProbableHttp(data, length)) {
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val request = String(data, 0, headerEnd - 4, Charsets.US_ASCII)
                        val modified = request + "\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5, max=1000\r\n\r\n"
                        output.write(modified.toByteArray(Charsets.US_ASCII))
                        output.write(data, headerEnd, length - headerEnd); output.flush()
                        return
                    }
                }
                val keepAlive = "OPTIONS * HTTP/1.1\r\nHost: $host\r\nConnection: keep-alive\r\n\r\n".toByteArray()
                output.write(keepAlive); output.flush(); delay(5)
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.HTTP_CONNECTION_CLOSE_SKEW -> {
                if (isProbableHttp(data, length)) {
                    val fakeHeader = "Connection: close\r\n".toByteArray()
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    val headerEnd = findHeaderEnd(data, length)
                    if (headerEnd != -1) {
                        val firstLineEnd = String(data, 0, headerEnd).indexOf("\r\n")
                        if (firstLineEnd != -1) {
                            output.write(data, 0, firstLineEnd + 2)
                            output.write(fakeHeader)
                            output.write(data, firstLineEnd + 2, length - (firstLineEnd + 2)); output.flush()
                        }
                    }
                    TtlHelper.setTtl(socket, 64)
                    delay(5)
                    output.write(data, 0, length); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            else -> {
                output.write(data, 0, length); output.flush()
            }
        }
    }

    private fun isProbableHttp(data: ByteArray, length: Int): Boolean {
        if (length < 4) return false
        val s = String(data, 0, 8.coerceAtMost(length))
        return s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("HEAD ") || 
               s.startsWith("PUT ") || s.startsWith("DELETE ") || s.startsWith("OPTIONS ")
    }

    private fun findHeaderEnd(data: ByteArray, length: Int): Int {
        for (i in 0 until length - 3) {
            if (data[i] == '\r'.code.toByte() && data[i+1] == '\n'.code.toByte() && 
                data[i+2] == '\r'.code.toByte() && data[i+3] == '\n'.code.toByte()) {
                return i + 4
            }
        }
        return -1
    }

    suspend fun handleTlsStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        when (strategy) {
            BypassStrategy.TLS_SNI_FRAGMENT -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1 && host.length > 2) {
                    val split1 = offset + 1
                    val split2 = offset + host.length - 1
                    output.write(data, 0, split1); output.flush(); delay(rnd.nextLong(1, 5))
                    output.write(data, split1, split2 - split1); output.flush(); delay(rnd.nextLong(1, 5))
                    output.write(data, split2, length - split2); output.flush()
                } else {
                    output.write(data, 0, length / 2); output.flush(); delay(2)
                    output.write(data, length / 2, length - (length / 2)); output.flush()
                }
            }
            BypassStrategy.TLS_MULTI_SNI -> {
                try {
                    val mod = FakePacketHelper.injectMultipleSni(data, length, host)
                    output.write(mod); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_CLIENT_HELLO_MULTI_PAD -> {
                val mod = FakePacketHelper.injectMultiTlsPadding(data, length, rnd.nextInt(2, 5))
                output.write(mod); output.flush()
            }
            BypassStrategy.TLS_SNI_JITTER_SPLIT -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1 && host.length > 3) {
                    val split1 = offset + rnd.nextInt(1, host.length / 2 + 1)
                    val split2 = split1 + rnd.nextInt(1, host.length - (split1 - offset))
                    output.write(data, 0, split1); output.flush(); delay(rnd.nextLong(10, 50))
                    output.write(data, split1, split2 - split1); output.flush(); delay(rnd.nextLong(20, 100))
                    output.write(data, split2, length - split2); output.flush()
                } else {
                    output.write(data, 0, length / 2); output.flush(); delay(5)
                    output.write(data, length / 2, length - (length / 2)); output.flush()
                }
            }
            BypassStrategy.TLS_HELLO_JUNK -> {
                try {
                    output.write(data, 0, length); output.flush()
                    delay(2)
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                } catch(e: Throwable) { try { output.write(data, 0, length); output.flush() } catch(e2: Throwable) {} }
            }
            BypassStrategy.TLS_ALPN_SKEW -> {
                try {
                    val mod = data.copyOf(length)
                    for (i in 0 until length - 2) {
                        if (mod[i] == 'h'.code.toByte() && mod[i+1] == '2'.code.toByte()) {
                            if (rnd.nextBoolean()) mod[i] = 'H'.code.toByte()
                        }
                    }
                    output.write(mod); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_REC_SPLIT, BypassStrategy.TLS_REC_MANGLE -> {
                try {
                    if (length > 5 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
                        val handshakeLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
                        if (handshakeLen + 5 <= length) {
                            val splitPos = rnd.nextInt(1, handshakeLen)
                            val header1 = data.copyOf(5)
                            header1[3] = ((splitPos shr 8) and 0xFF).toByte()
                            header1[4] = (splitPos and 0xFF).toByte()
                            output.write(header1)
                            output.write(data, 5, splitPos); output.flush()
                            val rem = handshakeLen - splitPos
                            if (rem > 0) {
                                val header2 = data.copyOf(5)
                                header2[3] = ((rem shr 8) and 0xFF).toByte()
                                header2[4] = (rem and 0xFF).toByte()
                                output.write(header2)
                                output.write(data, 5 + splitPos, rem); output.flush()
                            }
                        } else {
                            output.write(data, 0, length); output.flush()
                        }
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_RECORD_PADDING, BypassStrategy.TLS_HANDSHAKE_RANDOM_PADDING, BypassStrategy.TLS_CLIENT_HELLO_PAD, BypassStrategy.TLS_PAD -> {
                try {
                    val mod = FakePacketHelper.injectTlsPadding(data, length, rnd.nextInt(64, 512))
                    output.write(mod); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_SESSION_ID_RAND -> {
                try {
                    val mod = data.copyOf(length)
                    if (length > 43) {
                        val sidLen = mod[43].toInt() and 0xff
                        if (sidLen > 0 && sidLen <= 32 && 44 + sidLen <= length) {
                            for (i in 0 until sidLen) mod[44 + i] = rnd.nextInt(256).toByte()
                        }
                    }
                    output.write(mod); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_EXT_CHAOS -> {
                try {
                    val mod = FakePacketHelper.shuffleTlsExtensions(data, length)
                    val mod2 = FakePacketHelper.addTlsGreaseExtensions(mod, mod.size)
                    output.write(mod2); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_SNI_SKEW_ADVANCED -> {
                try {
                    val mod = FakePacketHelper.moveSniExtensionToEnd(data, length)
                    val mod2 = FakePacketHelper.injectExtension(mod, mod.size, 0x0000, "google.com".toByteArray())
                    output.write(mod2); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_RECORD_FRAGMENTATION -> {
                if (length > 5 && (data[0] == 0x16.toByte() || data[0] == 0x17.toByte())) {
                    val head = 5
                    val bodyLen = length - head
                    val maxChunk = 20
                    var sent = 0
                    while (sent < bodyLen) {
                        val remaining = bodyLen - sent
                        if (remaining <= 0) break
                        val cur = rnd.nextInt(5, maxChunk.coerceAtLeast(6)).coerceAtMost(remaining).coerceAtLeast(1)
                        val record = ByteArray(5 + cur)
                        record[0] = data[0]; record[1] = data[1]; record[2] = data[2]
                        record[3] = (cur shr 8).toByte(); record[4] = (cur and 0xFF).toByte()
                        System.arraycopy(data, head + sent, record, 5, cur)
                        output.write(record); output.flush()
                        sent += cur
                        if (sent < bodyLen) delay(rnd.nextLong(1, 3))
                    }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_SNI_SPLIT -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val sniOffset = TlsParser.findSniOffset(data, length)
                    if (sniOffset != -1 && sniOffset > 5) {
                        val splitPos = (sniOffset - 3).coerceAtLeast(5)
                        output.write(data, 0, splitPos); output.flush()
                        delay(rnd.nextLong(2, 10))
                        output.write(data, splitPos, length - splitPos); output.flush()
                    } else {
                        val part = length / 2
                        output.write(data, 0, part); output.flush()
                        delay(rnd.nextLong(2, 10))
                        output.write(data, part, length - part); output.flush()
                    }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_CLIENT_HELLO_REORDER, BypassStrategy.TLS_CLIENT_HELLO_SHUFFLE -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val shuffled = FakePacketHelper.shuffleTlsExtensions(data, length)
                    output.write(shuffled); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_CLIENT_HELLO_GREASE_RANDOM, BypassStrategy.TLS_DIRTY -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val mangled = FakePacketHelper.addTlsGreaseExtensions(data, length)
                    output.write(mangled); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_SESSION_ID_MANGLE -> {
                if (length > 44 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()) {
                    val mod = FakePacketHelper.mangleSessionId(data, length)
                    output.write(mod); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_SNI_GREASE -> {
                val greased = FakePacketHelper.injectTlsGrease(data, length)
                output.write(greased); output.flush()
            }
            BypassStrategy.TLS_REC_CHOP -> {
                if (length > 5 && data[0] == 0x16.toByte()) {
                    val bodyLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
                    if (bodyLen + 5 <= length) {
                        var pos = 5
                        val maxPos = 5 + bodyLen
                        while (pos < maxPos) {
                            val remaining = maxPos - pos
                            val chunk = rnd.nextInt(1, 5).coerceAtMost(remaining).coerceAtLeast(1)
                            val header = data.copyOfRange(0, 5)
                            header[3] = ((chunk shr 8) and 0xFF).toByte()
                            header[4] = (chunk and 0xFF).toByte()
                            output.write(header); output.write(data, pos, chunk); output.flush()
                            pos += chunk
                            delay(rnd.nextLong(1, 3))
                        }
                    } else { output.write(data, 0, length); output.flush() }
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TLS_MULTI_FRAG -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(5, 20).coerceAtMost(length - pos)
                    output.write(data, pos, sz); output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(1, 5))
                }
            }
            BypassStrategy.FRAGMENT_MULTI -> {
                var pos = 0
                val count = rnd.nextInt(3, 10)
                while (pos < length) {
                    val sz = (length / count).coerceAtLeast(1).coerceAtMost(length - pos)
                    output.write(data, pos, sz); output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(2, 8))
                }
            }
            BypassStrategy.SLOW_SEND -> {
                for (i in 0 until length) {
                    output.write(data[i].toInt()); output.flush()
                    delay(rnd.nextLong(5, 15))
                }
            }
            BypassStrategy.DNS_OVER_TCP, BypassStrategy.DNS_CASE_MANGLE -> {
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.QUIC_MTU_PROBE -> {
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.ECH_GREASE -> {
                val greased = FakePacketHelper.injectEchGrease(data, length)
                output.write(greased); output.flush()
            }
            BypassStrategy.TLS_ECH_FAKE -> {
                val fakeEch = FakePacketHelper.buildFakeEchExtension()
                val mod = FakePacketHelper.injectExtension(data, length, 0xfe0d, fakeEch)
                output.write(mod); output.flush()
            }
            BypassStrategy.TLS_SNI_SKEW -> {
                output.write(data, 0, length); output.flush()
            }

            else -> {
                output.write(data, 0, length); output.flush()
            }
        }
    }

    suspend fun handleTcpStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy) {
        when (strategy) {
            BypassStrategy.TCP_WINDOW_SIZE_SKEW -> {
                try {
                    val split = (length / 3).coerceAtLeast(1)
                    socket.receiveBufferSize = 1
                    output.write(data, 0, split); output.flush()
                    delay(rnd.nextLong(20, 100))
                    socket.receiveBufferSize = 65535
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_WINDOW_SHRINK -> {
                try {
                    socket.receiveBufferSize = rnd.nextInt(16, 64)
                    output.write(data, 0, length); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_ZERO_WINDOW_OOB -> {
                try {
                    socket.receiveBufferSize = 0
                    delay(rnd.nextLong(20, 100))
                    try { socket.sendUrgentData(0xFF) } catch(e: Throwable) {}
                    socket.receiveBufferSize = 1
                    val split = (length / 2).coerceAtLeast(1)
                    output.write(data, 0, split); output.flush()
                    delay(rnd.nextLong(50, 200))
                    socket.receiveBufferSize = 16384
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_SYN_FLOOD_FAKE -> {
                repeat(rnd.nextInt(2, 5)) {
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(rnd.nextLong(1, 5))
                }
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_OOB_SEGMENTATION -> {
                val chunks = rnd.nextInt(3, 7)
                var pos = 0
                while (pos < length) {
                    val remaining = length - pos
                    if (remaining <= 0) break
                    val sz = (remaining / (chunks - (pos * chunks / length).coerceAtMost(chunks - 1))).coerceAtLeast(1)
                    output.write(data, pos, sz); output.flush()
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(1, 10))
                }
            }
            BypassStrategy.TCP_WINDOW_SHAKE -> {
                try {
                    val originalSize = socket.receiveBufferSize
                    socket.receiveBufferSize = rnd.nextInt(128, 512)
                    output.write(data, 0, length / 2); output.flush()
                    delay(rnd.nextLong(10, 50))
                    socket.receiveBufferSize = originalSize + rnd.nextInt(1, 1024)
                    output.write(data, length / 2, length - (length / 2)); output.flush()
                } catch (e: Throwable) {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_BYTE_FRAG -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1 && host.isNotEmpty()) {
                    output.write(data, 0, offset); output.flush()
                    delay(5)
                    var pos = offset
                    while (pos < offset + host.length) {
                        val chunk = minOf(2, offset + host.length - pos)
                        output.write(data, pos, chunk); output.flush()
                        delay(rnd.nextLong(1, 4))
                        pos += chunk
                    }
                    output.write(data, pos, length - pos); output.flush()
                } else {
                    var pos = 0
                    while (pos < length) {
                        val chunk = rnd.nextInt(1, 5).coerceAtMost(length - pos)
                        output.write(data, pos, chunk); output.flush()
                        if (pos < length / 2) delay(rnd.nextLong(1, 3))
                        pos += chunk
                    }
                }
            }
            BypassStrategy.TCP_DATA_REPETITION -> {
                try {
                    val split = (length / 2).coerceAtLeast(1)
                    output.write(data, 0, split); output.flush()
                    delay(5)
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(1)
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_RETRANS_FAKE -> {
                try {
                    val split = (length / 2).coerceAtLeast(1)
                    val discoveredTtl = AutoTtlProber.getDiscoveredTtl(host) ?: 4
                    output.write(data, 0, split); output.flush()
                    delay(rnd.nextLong(10, 30))
                    val oldTtl = TtlHelper.getSocketTtl(socket)
                    TtlHelper.setTtl(socket, discoveredTtl)
                    val fakePart = FakePacketHelper.buildUdpNoise(length - split)
                    output.write(fakePart); output.flush()
                    delay(rnd.nextLong(20, 50))
                    TtlHelper.setTtl(socket, oldTtl)
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_OVERLAP_SKEW -> {
                try {
                    val offset = TlsParser.findSniOffset(data, length, host)
                    val split = if (offset != -1) offset + 2 else (length / 2).coerceIn(1, length - 1)
                    val discoveredTtl = AutoTtlProber.getDiscoveredTtl(host) ?: 3
                    output.write(data, 0, split); output.flush()
                    val oldTtl = TtlHelper.getSocketTtl(socket)
                    TtlHelper.setTtl(socket, discoveredTtl)
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(rnd.nextLong(15, 50))
                    TtlHelper.setTtl(socket, oldTtl)
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_OOB_DESYNC -> {
                try {
                    val split = (length / 2).coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush()
                    try { socket.sendUrgentData(rnd.nextInt(32, 126)) } catch (e: Throwable) {}
                    delay(rnd.nextLong(10, 30))
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_ZERO_WINDOW_STALL -> {
                try {
                    val originalSize = socket.receiveBufferSize
                    val split = if (length > 3) rnd.nextInt(1, 4) else 1
                    output.write(data, 0, split); output.flush()
                    val cycles = if (ProxyStats.censorshipIntensity.value > 80) rnd.nextInt(3, 6) else rnd.nextInt(2, 4)
                    for (i in 0 until cycles) {
                        try { socket.receiveBufferSize = 1 } catch (e: Throwable) {}
                        delay(rnd.nextLong(40, 100))
                        val currentPos = split + i
                        if (currentPos < length) {
                            output.write(data, currentPos, 1); output.flush()
                        }
                    }
                    try { socket.receiveBufferSize = originalSize.coerceAtLeast(65536) } catch (e: Throwable) {}
                    val finalSentPos = split + cycles
                    if (length > finalSentPos) {
                        delay(rnd.nextLong(15, 45))
                        output.write(data, finalSentPos, length - finalSentPos); output.flush()
                    } else {
                        output.flush()
                    }
                } catch (e: Throwable) { 
                    try { output.write(data, 0, length); output.flush() } catch(e2: Throwable) {}
                }
            }
            BypassStrategy.TCP_REORDER_SIM -> {
                try {
                    if (length > 20) {
                        val split = length / 2
                        val p1 = data.copyOfRange(0, split)
                        val p2 = data.copyOfRange(split, length)
                        output.write(p2); output.flush()
                        delay(rnd.nextLong(5, 15))
                        output.write(p1); output.flush()
                    } else {
                        output.write(data, 0, length); output.flush()
                    }
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_OVERLAP -> {
                try {
                    val offset = TlsParser.findSniOffset(data, length, host)
                    val split = if (offset != -1) offset + 1 else (length / 2).coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush()
                    val ghostLen = minOf(length - split, 48)
                    if (ghostLen > 0) {
                        try {
                             val ghostData = FakePacketHelper.buildHandshakeCombo(ghostLen)
                             TtlHelper.setTtl(socket, rnd.nextInt(2, 6))
                             output.write(ghostData); output.flush()
                        } catch(e: Throwable) {}
                    }
                    TtlHelper.setTtl(socket, 64)
                    delay(5)
                    output.write(data, split, length - split); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_REORDER_CHAOS -> {
                val split = length / 2
                if (split > 0) {
                    val discoveredTtl = AutoTtlProber.getDiscoveredTtl(host) ?: 3
                    TtlHelper.setTtl(socket, discoveredTtl)
                    output.write(FakePacketHelper.buildHandshakeCombo(split)); output.flush()
                    delay(5)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, split); output.flush()
                    delay(5)
                    output.write(data, split, length - split); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TCP_URGENT_RANDOM, BypassStrategy.TCP_URGENT_SKEW -> {
                try {
                    val split = (length / 2).coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush()
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                    delay(5)
                    output.write(data, split, length - split); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_WINDOW_RESTRICT -> {
                try {
                    val originalSize = socket.receiveBufferSize
                    socket.receiveBufferSize = rnd.nextInt(32, 256)
                    val split = length / 2
                    output.write(data, 0, split); output.flush()
                    delay(5)
                    socket.receiveBufferSize = originalSize.coerceAtLeast(65536)
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_FAST_OPEN_FAKE, BypassStrategy.TCP_GHOST_SKEW, BypassStrategy.TCP_RANDOM_PADDING -> {
                try {
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(5)
                    output.write(data, 0, length); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_WINDOW_SIZE_CHAOS -> {
                try {
                    socket.sendBufferSize = rnd.nextInt(128, 4096)
                    output.write(data, 0, length / 2); output.flush()
                    delay(rnd.nextLong(1, 10))
                    socket.sendBufferSize = rnd.nextInt(4096, 65536)
                    output.write(data, length / 2, length - (length / 2)); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_ZERO_WINDOW_DESYNC -> {
                try {
                    socket.receiveBufferSize = 1
                    val split = (length / 2).coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush()
                    delay(rnd.nextLong(500, 1500))
                    socket.receiveBufferSize = 65536
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_REORDER_DESYNC -> {
                try {
                    val split = (length / 2).coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush()
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    output.write(data, split, length - split); output.flush()
                    TtlHelper.setTtl(socket, 64)
                    delay(5)
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    output.write(data, split, length - split); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_ACK_DELAY -> {
                try {
                    val split = (length / 2).coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush()
                    delay(rnd.nextLong(100, 300))
                    output.write(data, split, length - split); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_WINDOW_CLAMPING, BypassStrategy.TCP_TOS_MANGLE -> {
                try {
                    if (strategy == BypassStrategy.TCP_WINDOW_CLAMPING) {
                        socket.receiveBufferSize = rnd.nextInt(256, 1024)
                        socket.sendBufferSize = rnd.nextInt(256, 1024)
                    } else {
                        socket.trafficClass = listOf(0x04, 0x08, 0x10, 0x02).random()
                    }
                } catch (e: Throwable) {}
                output.write(data, 0, length); output.flush()
            }
            BypassStrategy.TCP_RST_FAKE, BypassStrategy.TCP_KEEP_ALIVE_FAKE, BypassStrategy.HTTP2_PREAMBLE_FAKE -> {
                try {
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(5)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, length); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_HANDSHAKE_CHAOS -> {
                try {
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(10)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, length); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_WINDOW_RESIZE_PACING -> {
                try {
                    val p1 = length / 2
                    socket.sendBufferSize = 128
                    output.write(data, 0, p1); output.flush()
                    delay(5)
                    socket.sendBufferSize = 65535
                    output.write(data, p1, length - p1); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_KEEPALIVE_SKEW -> {
                try {
                    socket.keepAlive = true
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(1)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, length); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_URGENT_DESYNC -> {
                val split = (length / 2).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush()
                try { socket.sendUrgentData(rnd.nextInt(256)); delay(1) } catch (e: Throwable) {}
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_DATA_OOB_SKEW -> {
                var pos = 0
                while (pos < length) {
                    val remaining = length - pos
                    val sz = rnd.nextInt(10, 50).coerceAtMost(remaining).coerceAtLeast(1)
                    output.write(data, pos, sz); output.flush()
                    pos += sz
                    if (pos < length && rnd.nextInt(100) < 30) {
                        try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                        delay(rnd.nextLong(1, 10))
                    }
                }
            }
            BypassStrategy.TCP_SACK_FAKE -> {
                if (length > 20) {
                    val part = length / 2
                    output.write(data, 0, part); output.flush()
                    try { socket.sendUrgentData(0) } catch (e: Throwable) {}
                    delay(rnd.nextLong(5, 15))
                    output.write(data, part, length - part); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_MSS_CLAMPER, BypassStrategy.TCP_MSS_CLAMP -> {
                val mss = rnd.nextInt(256, 512)
                TtlHelper.setMss(socket, mss)
                var pos = 0
                while (pos < length) {
                    val len = minOf(mss, length - pos)
                    output.write(data, pos, len); output.flush()
                    pos += len
                    if (pos < length) delay(rnd.nextLong(1, 3))
                }
                TtlHelper.setMss(socket, 1400)
            }
            BypassStrategy.TCP_SEGMENT_DESYNC -> {
                try {
                    val split = (length / 2).coerceIn(1, length - 1)
                    output.write(data, 0, split); output.flush()
                    TtlHelper.setTtl(socket, 3)
                    output.write(FakePacketHelper.buildUdpNoise(length - split)); output.flush()
                    delay(rnd.nextLong(10, 30))
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, split, length - split); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_TIMING_CHAOS -> {
                val chunks = rnd.nextInt(4, 8)
                for (i in 0 until chunks) {
                    val s = i * (length / chunks)
                    val e = if (i == chunks - 1) length else (i + 1) * (length / chunks)
                    if (e > s) {
                        output.write(data, s, e - s); output.flush()
                        delay(rnd.nextLong(5, 50))
                    }
                }
            }
            BypassStrategy.TCP_ACK_SKEW -> {
                output.write(data, 0, 1); output.flush()
                delay(rnd.nextLong(1, 5))
                output.write(data, 1, length - 1); output.flush()
            }
            BypassStrategy.TCP_ACK_SKEW_ADVANCED -> {
                output.write(data, 0, 1); output.flush()
                delay(rnd.nextLong(5, 20))
                if (length > 1) {
                    val s2 = (length - 1) / 2
                    output.write(data, 1, s2); output.flush()
                    delay(rnd.nextLong(2, 10))
                    output.write(data, 1 + s2, length - 1 - s2); output.flush()
                }
            }
            BypassStrategy.TCP_FOOL_DPI -> {
                try {
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 4))
                    output.write(FakePacketHelper.buildHandshakeCombo(rnd.nextInt(32, 64))); output.flush()
                    delay(rnd.nextLong(2, 10))
                    socket.receiveBufferSize = 1
                    TtlHelper.setTtl(socket, 64)
                    output.write(data[0].toInt()); output.flush()
                    delay(rnd.nextLong(5, 20))
                    socket.receiveBufferSize = 65536
                    if (length > 1) { output.write(data, 1, length - 1); output.flush() }
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_DATA_DESYNC_OVERLAP -> {
                try {
                    val split = if (length > 20) length / 2 else 1
                    output.write(data, 0, split); output.flush()
                    TtlHelper.setTtl(socket, 3)
                    output.write(data, split, length - split); output.flush()
                    output.write(FakePacketHelper.buildUdpNoise(rnd.nextInt(20, 64))); output.flush()
                    delay(rnd.nextLong(20, 50))
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_REVERSE_FRAG -> {
                if (length > 10) {
                    val split = length / 2
                    output.write(data, 0, split); output.flush()
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                    delay(rnd.nextLong(1, 5))
                    output.write(data, split, length - split); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_FRAGMENT_REORDER -> {
                if (length > 15) {
                    val s1 = length / 3
                    val s2 = (length * 2) / 3
                    output.write(data, 0, s1); output.flush()
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                    delay(1)
                    output.write(data, s1, s2 - s1); output.flush()
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                    delay(5)
                    output.write(data, s2, length - s2); output.flush()
                } else { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_SMALL_CHUNKS -> {
                var pos = 0
                val chunkSize = rnd.nextInt(2, 8)
                while (pos < length) {
                    val len = minOf(chunkSize, length - pos)
                    output.write(data, pos, len); output.flush()
                    pos += len
                    if (pos < length) delay(rnd.nextLong(1, 4))
                }
            }
            BypassStrategy.TCP_TIMESTAMP_MANGLE -> {
                output.write(data, 0, 1); output.flush()
                try { socket.sendUrgentData(rnd.nextInt(256)) } catch (e: Throwable) {}
                delay(5)
                output.write(data, 1, length - 1); output.flush()
            }
            BypassStrategy.TCP_WINDOW_SCAN -> {
                socket.receiveBufferSize = 512
                output.write(data, 0, 1); output.flush()
                delay(5)
                socket.receiveBufferSize = 65536
                output.write(data, 1, length - 1); output.flush()
            }
            BypassStrategy.WINDOW_SIZE_MANGLE -> {
                socket.receiveBufferSize = rnd.nextInt(256, 1024)
                val split = (length / 2).coerceIn(1, length - 1)
                output.write(data, 0, split); output.flush()
                delay(5)
                socket.receiveBufferSize = 65536
                output.write(data, split, length - split); output.flush()
            }
            BypassStrategy.TCP_MSS_CLUMPING -> {
                val mss = rnd.nextInt(400, 800)
                var offset = 0
                while (offset < length) {
                    val sz = minOf(mss, length - offset)
                    output.write(data, offset, sz); output.flush()
                    offset += sz
                    if (offset < length) delay(rnd.nextLong(2, 5))
                }
            }
            BypassStrategy.TCP_SACK_PANIC, BypassStrategy.TCP_SACK_SKEW -> {
                try {
                    output.write(data, 0, length); output.flush()
                } catch(e: Throwable) {}
            }
            BypassStrategy.ADAPTIVE_CHUNK -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(1, 10).coerceAtMost(length - pos)
                    output.write(data, pos, sz); output.flush()
                    pos += sz
                    delay(rnd.nextLong(1, 3))
                }
            }
            BypassStrategy.PROTOCOL_CONFUSION_REDIS -> {
                val fake = FakePacketHelper.buildProtocolConfusion("REDIS")
                try {
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    output.write(fake); output.flush()
                    delay(5)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, length); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.PROTOCOL_CONFUSION_MEMCACHED -> {
                val fake = FakePacketHelper.buildProtocolConfusion("MEMCACHED")
                try {
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    output.write(fake); output.flush()
                    delay(5)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, length); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_SEGMENT_OVERLAP -> {
                try {
                    val split = (length / 2).coerceAtLeast(1)
                    val discoveredTtl = AutoTtlProber.getDiscoveredTtl(host) ?: 3
                    output.write(data, 0, split); output.flush()
                    val oldTtl = TtlHelper.getSocketTtl(socket)
                    TtlHelper.setTtl(socket, discoveredTtl)
                    output.write(FakePacketHelper.buildUdpNoise(length - split)); output.flush()
                    delay(rnd.nextLong(10, 30))
                    TtlHelper.setTtl(socket, oldTtl)
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.TCP_SEGMENT_REVERSE -> {
                try {
                    val split = (length / 2).coerceAtLeast(1)
                    val discoveredTtl = AutoTtlProber.getDiscoveredTtl(host) ?: 3
                    val oldTtl = TtlHelper.getSocketTtl(socket)
                    TtlHelper.setTtl(socket, discoveredTtl)
                    output.write(data, split, length - split); output.flush()
                    TtlHelper.setTtl(socket, oldTtl)
                    output.write(data, 0, split); output.flush()
                    delay(5)
                    output.write(data, split, length - split); output.flush()
                } catch (e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            else -> {
                output.write(data, 0, length); output.flush()
            }
        }
    }

    suspend fun handleFragmentationStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, effectiveDelay: Long) {
        when (strategy) {
            BypassStrategy.SNI_SPLIT -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                val split = if (offset != -1) offset + 1 else length / 2
                val safeSplit = split.coerceIn(1, length - 1)
                output.write(data, 0, safeSplit); output.flush(); delay(effectiveDelay)
                output.write(data, safeSplit, length - safeSplit); output.flush()
            }
            BypassStrategy.TLS_SNI_SYMMETRIC_SPLIT -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                val split = if (offset != -1 && host.isNotEmpty()) offset + (host.length / 2) else length / 2
                val safeSplit = split.coerceIn(1, length - 1)
                output.write(data, 0, safeSplit); output.flush(); delay(effectiveDelay)
                output.write(data, safeSplit, length - safeSplit); output.flush()
            }
            BypassStrategy.SNI_TRIPLE -> {
                val offset = TlsParser.findSniOffset(data, length, host)
                if (offset != -1 && length > offset + host.length + 1) {
                    val part1 = (host.length / 3).coerceAtLeast(1)
                    val part2 = (2 * host.length / 3).coerceAtLeast(part1 + 1)
                    val s1 = offset + part1
                    val s2 = offset + part2
                    output.write(data, 0, s1); output.flush(); delay(effectiveDelay)
                    output.write(data, s1, s2 - s1); output.flush(); delay(effectiveDelay)
                    output.write(data, s2, length - s2); output.flush()
                } else {
                    val s1 = (length / 3).coerceIn(1, length - 2)
                    val s2 = (2 * length / 3).coerceIn(s1 + 1, length - 1)
                    output.write(data, 0, s1); output.flush(); delay(effectiveDelay)
                    output.write(data, s1, s2 - s1); output.flush(); delay(effectiveDelay)
                    output.write(data, s2, length - s2); output.flush()
                }
            }
            BypassStrategy.ECH_FRAG -> {
                val split1 = rnd.nextInt(2, 5)
                val split2 = rnd.nextInt(32, 64)
                output.write(data, 0, split1); output.flush()
                delay(rnd.nextLong(1, 5))
                output.write(data, split1, split2 - split1); output.flush()
                delay(rnd.nextLong(1, 10))
                if (ProxyStats.censorshipIntensity.value > 60) {
                    val discoveredTtl = AutoTtlProber.getDiscoveredTtl(host) ?: 4
                    val oldTtl = TtlHelper.getSocketTtl(socket)
                    TtlHelper.setTtl(socket, discoveredTtl)
                    val fake = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 64))
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(rnd.nextLong(5, 15))
                    TtlHelper.setTtl(socket, oldTtl)
                }
                output.write(data, split2, length - split2); output.flush()
            }
            BypassStrategy.TLS_APP_DATA_SPLIT -> {
                if (length > 5 && data[0] == 0x17.toByte()) {
                    val s1 = length / 3
                    val s2 = 2 * length / 3
                    output.write(data, 0, s1); output.flush(); delay(effectiveDelay)
                    output.write(data, s1, s2 - s1); output.flush(); delay(effectiveDelay)
                    output.write(data, s2, length - s2); output.flush()
                } else {
                    output.write(data, 0, length); output.flush()
                }
            }
            BypassStrategy.TLS_CLIENT_HELLO_CHOP -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(1, 4).coerceAtMost(length - pos)
                    output.write(data, pos, sz); output.flush()
                    pos += sz
                    if (pos < length) delay(rnd.nextLong(1, 3))
                }
            }
            else -> {
                output.write(data, 0, length); output.flush()
            }
        }
    }

    suspend fun handleAdaptiveStrategies(socket: Socket, output: OutputStream, data: ByteArray, length: Int, rnd: ThreadLocalRandom, host: String, strategy: BypassStrategy, config: SessionConfig) {
        when (strategy) {
            BypassStrategy.BYEBYEDPI_SIM, BypassStrategy.BYEBYEDPI_HYBRID -> {
                val split = config.frag1.coerceIn(1, length - 1)
                try {
                    TtlHelper.setTtl(socket, 2)
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(config.delay1)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, split); output.flush()
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(config.delay2)
                    output.write(data, split, length - split); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.BYEBYEDPI_EXTREME, BypassStrategy.ZAPRET_EXTREME -> {
                val split = length / 3
                try {
                    TtlHelper.setTtl(socket, 2)
                    output.write(data, 0, split); output.flush()
                    delay(config.delay1)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, split, length - split); output.flush()
                } catch(e: Throwable) { output.write(data, 0, length); output.flush() }
            }
            BypassStrategy.CHAOS -> {
                val subStrategies = when (HostClassifier.classify(host)) {
                    HostCategory.STREAMING -> listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TCP_WINDOW_SHRINK, BypassStrategy.FRAGMENT_MULTI)
                    HostCategory.SOCIAL -> listOf(BypassStrategy.TLS_SNI_SKEW_ADVANCED, BypassStrategy.TCP_RETRANS_FAKE, BypassStrategy.OOB_DESYNC)
                    else -> listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.TLS_GREASE, BypassStrategy.TCP_URGENT_SKEW)
                }
                val picked = subStrategies.random()
                when (picked.family) {
                    StrategyFamily.TCP -> handleTcpStrategies(socket, output, data, length, rnd, host, picked)
                    StrategyFamily.TLS -> handleTlsStrategies(socket, output, data, length, rnd, host, picked)
                    StrategyFamily.FRAGMENTATION -> handleFragmentationStrategies(socket, output, data, length, rnd, host, picked, config.delay1)
                    else -> { output.write(data, 0, length); output.flush() }
                }
            }
            BypassStrategy.TCP_COMBINED_HYBRID, BypassStrategy.TCP_COMBINED_NUCLEAR -> {
                // Highly disruptive multi-stage bypass
                try {
                    val split1 = (length / 4).coerceAtLeast(1)
                    val split2 = (length / 2).coerceAtLeast(split1 + 1)
                    
                    // Stage 1: Send garbage with low TTL
                    TtlHelper.setTtl(socket, rnd.nextInt(2, 5))
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    val fake = FakePacketHelper.buildProtocolConfusion("TCP")
                    output.write(fake); output.flush()
                    
                    // Stage 2: Wait and send first part
                    delay(config.delay1)
                    TtlHelper.setTtl(socket, 64)
                    output.write(data, 0, split1); output.flush()
                    
                    // Stage 3: Send more urgent data / skew
                    try { socket.sendUrgentData(rnd.nextInt(256)) } catch(e: Throwable) {}
                    delay(config.delay2)
                    output.write(data, split1, split2 - split1); output.flush()
                    
                    // Stage 4: Finish
                    delay(config.delay2)
                    output.write(data, split2, length - split2); output.flush()
                } catch(e: Throwable) { 
                    output.write(data, 0, length); output.flush() 
                }
            }
            else -> {
                output.write(data, 0, length); output.flush()
            }
        }
    }

    suspend fun handleUdpStrategies(
        socket: DatagramSocket,
        packet: DatagramPacket,
        rnd: ThreadLocalRandom,
        host: String,
        strategy: BypassStrategy,
        config: SessionConfig
    ) {
        val data = packet.data
        val length = packet.length
        val offset = packet.offset
        val targetAddr = packet.address
        val targetPort = packet.port ?: return
        val isIpv6 = targetAddr is java.net.Inet6Address

        when (strategy) {
            BypassStrategy.UDP_FAKE_DTLS -> {
                val fake = byteArrayOf(0x16, 0xfe.toByte(), 0xff.toByte()) + ByteArray(rnd.nextInt(10, 30)) { rnd.nextInt(256).toByte() }
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_WIREGUARD_FAKE -> {
                val fake = byteArrayOf(0x01, 0x00, 0x00, 0x00) + ByteArray(28) { rnd.nextInt(256).toByte() }
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_NOISE_CHAOS -> {
                repeat(rnd.nextInt(1, 3)) {
                    val noiseSize = rnd.nextInt(20, 100)
                    val noise = FakePacketHelper.buildUdpNoise(noiseSize)
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 6), isIpv6)
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch(e: Throwable) {}
                }
                if (rnd.nextBoolean()) delay(rnd.nextLong(1, 5))
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
                if (rnd.nextInt(100) < 50) {
                    val postNoise = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 40))
                    try { socket.send(DatagramPacket(postNoise, postNoise.size, targetAddr, targetPort)) } catch(e: Throwable) {}
                }
            }
            BypassStrategy.UDP_BURST_CHAOS -> {
                val burstSize = rnd.nextInt(3, 6)
                repeat(burstSize) {
                    val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(32, 128))
                    TtlHelper.setUdpTtl(socket, if (it % 2 == 0) rnd.nextInt(2, 6) else 64, isIpv6)
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch(e: Throwable) {}
                    if (rnd.nextBoolean()) delay(1)
                }
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
                val tail = FakePacketHelper.buildUdpNoise(rnd.nextInt(20, 60))
                try { socket.send(DatagramPacket(tail, tail.size, targetAddr, targetPort)) } catch(e: Throwable) {}
            }
            BypassStrategy.UDP_STUN_FAKE -> {
                val fake = byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4.toByte(), 0x42) + ByteArray(12) { rnd.nextInt(256).toByte() }
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_DATA_FRAG -> {
                if (length > 200) {
                    val randomNoise = FakePacketHelper.buildUdpNoise(length)
                    try {
                        TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 4), isIpv6)
                        socket.send(DatagramPacket(randomNoise, randomNoise.size, targetAddr, targetPort))
                        delay(rnd.nextLong(1, 3))
                    } catch (e: Throwable) {}
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                }
                socket.send(packet)
            }
            BypassStrategy.UDP_FRAGMENT_SKEW -> {
                if (length > 60 && targetPort != 53) {
                    val fake = ByteArray(length) { rnd.nextInt(256).toByte() }
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                    socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
                    delay(config.delay1)
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    socket.send(packet)
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_NOISE_PAD -> {
                if (rnd.nextInt(100) < 20) {
                    val preNoise = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 48))
                    try { socket.send(DatagramPacket(preNoise, preNoise.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                }
                socket.send(packet)
                if (rnd.nextInt(100) < 30) {
                    val noise = ByteArray(rnd.nextInt(10, 50)) { rnd.nextInt(256).toByte() }
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                }
            }
            BypassStrategy.UDP_QUIC_PAD -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val padding = ByteArray(rnd.nextInt(256, 512)) { 0x00 }
                    val combined = data.copyOfRange(offset, offset + length) + padding
                    socket.send(DatagramPacket(combined, combined.size, targetAddr, targetPort))
                    if (rnd.nextInt(100) < 20) {
                        val vn = FakePacketHelper.buildQuicVersionNegotiation()
                        socket.send(DatagramPacket(vn, vn.size, targetAddr, targetPort))
                    }
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_QUIC_JITTER_PAD -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val padSize = rnd.nextInt(128, 768)
                    val combined = data.copyOfRange(offset, offset + length) + FakePacketHelper.buildQuicJitterPad(padSize)
                    socket.send(DatagramPacket(combined, combined.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_QUIC_SMART_SHADOW -> {
                TtlHelper.setUdpTtl(socket, 3, isIpv6)
                val shadow = FakePacketHelper.buildQuicCryptoFake()
                try { socket.send(DatagramPacket(shadow, shadow.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                delay(2)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.UDP_SKEW_ADVANCED -> {
                try {
                    val fakePayload = data.copyOfRange(offset, offset + length) + FakePacketHelper.buildUdpNoise(rnd.nextInt(20, 100))
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                    socket.send(DatagramPacket(fakePayload, fakePayload.size, targetAddr, targetPort))
                    delay(rnd.nextLong(2, 8))
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    socket.send(packet)
                } catch(e: Throwable) { socket.send(packet) }
            }
            BypassStrategy.UDP_OVERLAP_SKEW -> {
                try {
                    val overlapSize = (length / 4).coerceAtLeast(1).coerceAtMost(16)
                    val fakePayload = data.copyOfRange(offset, offset + overlapSize)
                    for (i in fakePayload.indices) fakePayload[i] = (fakePayload[i].toInt() xor 0xAA).toByte()
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 4), isIpv6)
                    socket.send(DatagramPacket(fakePayload, fakePayload.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 3))
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    socket.send(packet)
                } catch(e: Throwable) { socket.send(packet) }
            }
            BypassStrategy.QUIC_INITIAL_FRAGMENT -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val noise = FakePacketHelper.buildUdpNoise(128)
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch(e: Throwable) {}
                    delay(rnd.nextLong(1, 4))
                }
                socket.send(packet)
            }
            BypassStrategy.QUIC_INITIAL_PADDING_EXTREME -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val padding = ByteArray(rnd.nextInt(800, 1100)) { 0x00 }
                    val combined = data.copyOfRange(offset, offset + length) + padding
                    socket.send(DatagramPacket(combined, combined.size, targetAddr, targetPort))
                    val vn = FakePacketHelper.buildQuicVersionNegotiation()
                    socket.send(DatagramPacket(vn, vn.size, targetAddr, targetPort))
                    delay(rnd.nextLong(2, 8))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_IP_FRAG -> {
                try {
                    if (length > 200) {
                        TtlHelper.setNoFrag(socket, false)
                        socket.send(packet)
                        TtlHelper.setNoFrag(socket, true)
                    } else {
                        socket.send(packet)
                    }
                } catch (e: Throwable) { socket.send(packet) }
            }
            BypassStrategy.QUIC_INITIAL_FRAGMENTATION -> {
                if (length > 400 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val fakeQuic = FakePacketHelper.buildQuicInitialFake()
                    val ghost = java.net.DatagramPacket(fakeQuic, fakeQuic.size, targetAddr, targetPort)
                    try { 
                        TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5))
                        socket.send(ghost)
                        delay(rnd.nextLong(1, 4))
                        TtlHelper.setUdpTtl(socket, 64)
                    } catch(e: Throwable) {}
                }
                socket.send(packet)
            }
            BypassStrategy.UDP_IPv6_FRAG -> {
                if (isIpv6) {
                    val part1 = length / 2
                    val p1 = java.net.DatagramPacket(data, offset, part1, targetAddr, targetPort)
                    val p2 = java.net.DatagramPacket(data, offset + part1, length - part1, targetAddr, targetPort)
                    socket.send(p1)
                    delay(config.delay1)
                    socket.send(p2)
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.PROTOCOL_CONFUSION_QUIC -> {
                val fake = FakePacketHelper.buildProtocolConfusion("QUIC")
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.PROTOCOL_CONFUSION_DTLS -> {
                val fake = FakePacketHelper.buildProtocolConfusion("DTLS")
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_STUTTER -> {
                delay(rnd.nextLong(5, 25))
                socket.send(packet)
            }
            BypassStrategy.UDP_GHOST_SKEW -> {
                val ghost = FakePacketHelper.buildUdpNoise(rnd.nextInt(32, 64))
                TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                socket.send(DatagramPacket(ghost, ghost.size, targetAddr, targetPort))
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.UDP_TELEGRAM_FAKE -> {
                val fake = FakePacketHelper.buildUdpNoise(48)
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_COMBINED_NUCLEAR -> {
                val discoveredTtl = AutoTtlProber.getDiscoveredTtl(host) ?: 3
                try {
                    TtlHelper.setUdpTtl(socket, discoveredTtl, isIpv6)
                    val fake1 = FakePacketHelper.buildProtocolConfusion("DTLS")
                    socket.send(DatagramPacket(fake1, fake1.size, targetAddr, targetPort))
                    delay(1)
                    val fake2 = if (rnd.nextBoolean()) FakePacketHelper.buildQuicCryptoFake() else FakePacketHelper.buildProtocolConfusion("QUIC")
                    socket.send(DatagramPacket(fake2, fake2.size, targetAddr, targetPort))
                    delay(rnd.nextLong(2, 8))
                } catch (e: Throwable) {}
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                if (ProxyStats.censorshipIntensity.value > 80 && rnd.nextBoolean()) {
                    socket.send(packet)
                    delay(1)
                }
                val chunkSize = rnd.nextInt(32, 256)
                var pos = offset
                while (pos < offset + length) {
                    val remaining = (offset + length) - pos
                    val sz = chunkSize.coerceAtMost(remaining)
                    if (remaining > 64 && rnd.nextInt(100) < 40) {
                        val junk = FakePacketHelper.buildUdpNoise(rnd.nextInt(16, 64))
                        try {
                            TtlHelper.setUdpTtl(socket, discoveredTtl, isIpv6)
                            socket.send(DatagramPacket(junk, junk.size, targetAddr, targetPort))
                            delay(1)
                            TtlHelper.setUdpTtl(socket, 64, isIpv6)
                        } catch (e: Throwable) {}
                    }
                    socket.send(DatagramPacket(data, pos, sz, targetAddr, targetPort))
                    pos += sz
                    if (pos < offset + length) delay(rnd.nextLong(2, 10))
                }
            }
            BypassStrategy.UDP_COMBINED_HYBRID -> {
                val noise = FakePacketHelper.buildHandshakeCombo(rnd.nextInt(64, 128))
                try {
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 4), isIpv6)
                    socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort))
                    delay(rnd.nextLong(1, 3))
                } catch (e: Throwable) {}
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                val split = (length / 2).coerceIn(1, length - 1)
                if (rnd.nextBoolean()) {
                    socket.send(DatagramPacket(data, offset + split, length - split, targetAddr, targetPort))
                    delay(rnd.nextLong(2, 5))
                    socket.send(DatagramPacket(data, offset, split, targetAddr, targetPort))
                } else {
                    socket.send(DatagramPacket(data, offset, split, targetAddr, targetPort))
                    delay(rnd.nextLong(2, 5))
                    socket.send(DatagramPacket(data, offset + split, length - split, targetAddr, targetPort))
                }
                if ((data[offset].toInt() and 0xC0) == 0xC0) {
                    val pad = FakePacketHelper.buildUdpNoise(rnd.nextInt(100, 300))
                    try { socket.send(DatagramPacket(pad, pad.size, targetAddr, targetPort)) } catch(e: Throwable) {}
                }
            }
            BypassStrategy.UDP_REPLICATION -> {
                if (rnd.nextInt(100) < 60) {
                    val padded = ByteArray(length + rnd.nextInt(4, 32))
                    System.arraycopy(data, offset, padded, 0, length)
                    socket.send(DatagramPacket(padded, padded.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.UDP_DISCORD_FAKE -> {
                val fake = FakePacketHelper.buildUdpNoise(64)
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_IKE_FAKE -> {
                val fake = FakePacketHelper.getCachedIke()
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_DHCP_FAKE -> {
                val fake = FakePacketHelper.getCachedDhcp()
                writeUdpWithFake(socket, targetAddr, targetPort, fake, packet, config)
            }
            BypassStrategy.UDP_DNS_REORDER_HYBRID -> {
                if (targetPort == 53) {
                    val fakeDns = FakePacketHelper.buildDnsFakeQuery("google.com")
                    try {
                        TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                        socket.send(DatagramPacket(fakeDns, fakeDns.size, targetAddr, targetPort))
                    } catch (e: Throwable) {}
                    delay(rnd.nextLong(2, 6))
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                    socket.send(packet)
                } else {
                    socket.send(packet)
                }
            }
            BypassStrategy.QUIC_RST_SKEW -> {
                val resetPacket = byteArrayOf(0x00, 0x00, 0x00, 0x00) + FakePacketHelper.buildUdpNoise(16)
                try {
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                    socket.send(DatagramPacket(resetPacket, resetPacket.size, targetAddr, targetPort))
                } catch (e: Throwable) {}
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.UDP_HEARTBEAT -> {
                val heartbeat = byteArrayOf(0x01, 0x00, 0x00, 0x00)
                try { socket.send(DatagramPacket(heartbeat, heartbeat.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                delay(2)
                socket.send(packet)
            }
            BypassStrategy.UDP_HIGH_VOL_PACING -> {
                val count = rnd.nextInt(2, 5)
                for (i in 0 until count) {
                    val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(8, 24))
                    try { socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                    delay(rnd.nextLong(1, 3))
                }
                socket.send(packet)
            }
            BypassStrategy.QUIC_INITIAL_FAKE -> {
                val fakeQuic = FakePacketHelper.buildQuicInitialFake()
                try {
                    TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                    socket.send(DatagramPacket(fakeQuic, fakeQuic.size, targetAddr, targetPort))
                } catch (e: Throwable) {}
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.DNS_NOISE -> {
                val fakeDns = FakePacketHelper.buildDnsFakeQuery("cloudflare.com")
                try { socket.send(DatagramPacket(fakeDns, fakeDns.size, targetAddr, targetPort)) } catch (e: Throwable) {}
                delay(2)
                socket.send(packet)
            }
            BypassStrategy.DNS_OVER_TCP_FORCE -> {
                socket.send(packet)
            }
            BypassStrategy.UDP_QUIC_SKEW -> {
                val fake = FakePacketHelper.buildQuicInitialFake()
                TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.UDP_REORDER -> {
                if (rnd.nextInt(100) < 40) delay(rnd.nextLong(2, 10))
                socket.send(packet)
                val padding = FakePacketHelper.buildUdpNoise(rnd.nextInt(10, 30))
                val fake = data.copyOfRange(offset, offset + length) + padding
                TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 4), isIpv6)
                socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
                delay(rnd.nextLong(2, 10))
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.UDP_ZERO_LEN_SKEW -> {
                if (rnd.nextBoolean()) {
                    val zero = ByteArray(0)
                    socket.send(DatagramPacket(zero, 0, targetAddr, targetPort))
                    delay(1)
                }
                socket.send(packet)
            }
            BypassStrategy.UDP_PADDING_CHAOS -> {
                val rndPad = rnd.nextInt(32, 256)
                val padded = data.copyOfRange(offset, offset + length) + FakePacketHelper.buildUdpNoise(rndPad)
                if (rnd.nextBoolean()) {
                     TtlHelper.setUdpTtl(socket, rnd.nextInt(3, 6), isIpv6)
                     socket.send(DatagramPacket(padded, padded.size, targetAddr, targetPort))
                     delay(1)
                     TtlHelper.setUdpTtl(socket, 64, isIpv6)
                }
                socket.send(DatagramPacket(padded, padded.size, targetAddr, targetPort))
            }
            BypassStrategy.UDP_FAKE_SESSION -> {
                val fakeVn = FakePacketHelper.buildQuicVersionNegotiation()
                TtlHelper.setUdpTtl(socket, 3, isIpv6)
                socket.send(DatagramPacket(fakeVn, fakeVn.size, targetAddr, targetPort))
                delay(rnd.nextLong(2, 10))
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.QUIC_VERSION_SKEW -> {
                if (length > 200 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val fakeVn = FakePacketHelper.buildQuicVersionNegotiation()
                    TtlHelper.setUdpTtl(socket, 3, isIpv6)
                    socket.send(DatagramPacket(fakeVn, fakeVn.size, targetAddr, targetPort))
                    delay(config.delay1)
                    TtlHelper.setUdpTtl(socket, 64, isIpv6)
                }
                socket.send(packet)
            }
            BypassStrategy.BYEBYEDPI_SIM -> {
                val fakeQuic = FakePacketHelper.buildQuicInitialFake()
                val noise = FakePacketHelper.buildUdpNoise(rnd.nextInt(64, 128))
                TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 5), isIpv6)
                socket.send(DatagramPacket(fakeQuic, fakeQuic.size, targetAddr, targetPort))
                delay(1)
                socket.send(DatagramPacket(noise, noise.size, targetAddr, targetPort))
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                socket.send(packet)
            }
            BypassStrategy.BYEBYEDPI_EXTREME, BypassStrategy.ZAPRET_EXTREME -> {
                val fakeQuic = FakePacketHelper.buildQuicInitialFake()
                val fakeQuic2 = FakePacketHelper.buildQuicVersionNegotiation()
                TtlHelper.setUdpTtl(socket, rnd.nextInt(2, 4), isIpv6)
                socket.send(DatagramPacket(fakeQuic, fakeQuic.size, targetAddr, targetPort))
                delay(1)
                TtlHelper.setUdpTtl(socket, rnd.nextInt(3, 5), isIpv6)
                socket.send(DatagramPacket(fakeQuic2, fakeQuic2.size, targetAddr, targetPort))
                delay(config.delay1)
                TtlHelper.setUdpTtl(socket, 64, isIpv6)
                if (length > 100 && (data[offset].toInt() and 0xC0) == 0xC0) {
                    val padding = ByteArray(rnd.nextInt(64, 128)) { 0x00 }
                    val combined = data.copyOfRange(offset, offset + length) + padding
                    socket.send(DatagramPacket(combined, combined.size, targetAddr, targetPort))
                } else {
                    socket.send(packet)
                }
            }
            else -> socket.send(packet)
        }
    }

    private suspend fun writeUdpWithFake(socket: DatagramSocket, targetAddr: InetAddress, targetPort: Int, fake: ByteArray, real: DatagramPacket, config: SessionConfig) {
        val isIpv6 = targetAddr is java.net.Inet6Address
        TtlHelper.setUdpTtl(socket, config.fakeTtl, isIpv6)
        socket.send(DatagramPacket(fake, fake.size, targetAddr, targetPort))
        delay(config.delay1)
        TtlHelper.setUdpTtl(socket, 64, isIpv6)
        socket.send(real)
    }
}

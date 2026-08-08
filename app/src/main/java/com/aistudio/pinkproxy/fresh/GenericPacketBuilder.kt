package com.aistudio.pinkproxy.fresh

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.concurrent.ThreadLocalRandom

object GenericPacketBuilder {

    fun buildQuicInitial(scid: String? = null): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val packet = ByteArray(1200)
        val buf = ByteBuffer.wrap(packet)
        
        // Header Form: 1 (Long), Fixed Bit: 1, Packet Type: 00 (Initial), Reserved Bits: 00, Packet Number Length: 00 (1 byte) -> 0xC0
        buf.put(0xC0.toByte())
        buf.putInt(0x00000001) // QUIC Version 1
        
        // DCID length: 8
        buf.put(8.toByte())
        val dcid = ByteArray(8); rnd.nextBytes(dcid); buf.put(dcid)
        
        // SCID length: 8
        buf.put(8.toByte())
        val scidBytes = scid?.toByteArray(StandardCharsets.UTF_8)?.take(8)?.toByteArray() ?: ByteArray(8).also { rnd.nextBytes(it) }
        buf.put(scidBytes)
        if (scidBytes.size < 8) buf.put(ByteArray(8 - scidBytes.size))
        
        // Token Length: 0 (varint 0x00)
        buf.put(0.toByte())
        
        // Payload Length: 1160 bytes (varint 2-byte encoding)
        val payloadLen = 1160
        buf.put(((payloadLen shr 8) or 0x40).toByte())
        buf.put((payloadLen and 0xFF).toByte())
        
        // Packet Number: 0x00
        buf.put(0.toByte())
        
        // Fill remainder with random encrypted payload simulation / PADDING frames (0x00)
        val payloadStart = buf.position()
        val payloadBytes = ByteArray(packet.size - payloadStart)
        rnd.nextBytes(payloadBytes)
        buf.put(payloadBytes)
        
        return packet
    }

    fun buildDtlsClientHello(): ByteArray {
        val data = ByteArray(60)
        val buf = ByteBuffer.wrap(data)
        buf.put(0x16.toByte()) // Handshake
        buf.putShort(0xfeff.toShort()) // DTLS 1.0
        buf.putShort(0.toShort()) // Epoch
        buf.putLong(0) // Sequence
        buf.putShort(47.toShort()) // Length
        buf.put(0x01.toByte()) // ClientHello
        return data
    }

    fun buildUdpProtocolFake(type: String): ByteArray {
        return when(type.uppercase()) {
            "DNS" -> byteArrayOf(0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)
            "DHCP" -> buildDhcpRequest()
            "STUN" -> buildStunBindingRequest()
            "WIREGUARD" -> buildWireguardHandshake()
            else -> buildQuicInitial()
        }
    }

    fun buildStunBindingRequest(): ByteArray {
        val data = ByteArray(20)
        val buf = ByteBuffer.wrap(data)
        buf.putShort(0x0001.toShort()) // Binding Request
        buf.putShort(0.toShort()) // Length
        buf.putInt(0x2112A442) // Magic Cookie
        val tid = ByteArray(12); ThreadLocalRandom.current().nextBytes(tid); buf.put(tid)
        return data
    }

    fun buildWireguardHandshake(): ByteArray {
        val rnd = ThreadLocalRandom.current()
        val data = ByteArray(148)
        data[0] = 0x01
        val buf = ByteBuffer.wrap(data)
        buf.position(4)
        buf.putInt(rnd.nextInt())
        
        val rndBytes = ByteArray(32); rnd.nextBytes(rndBytes); System.arraycopy(rndBytes, 0, data, 8, 32)
        val rndBytes48 = ByteArray(48); rnd.nextBytes(rndBytes48); System.arraycopy(rndBytes48, 0, data, 40, 48)
        val rndBytes28 = ByteArray(28); rnd.nextBytes(rndBytes28); System.arraycopy(rndBytes28, 0, data, 88, 28)
        val rndBytes16 = ByteArray(16); rnd.nextBytes(rndBytes16); System.arraycopy(rndBytes16, 0, data, 116, 16)
        rnd.nextBytes(rndBytes16); System.arraycopy(rndBytes16, 0, data, 132, 16)
        
        return data
    }

    fun buildIkeHandshake(): ByteArray {
        val data = ByteArray(28)
        val buf = ByteBuffer.wrap(data)
        buf.putLong(ThreadLocalRandom.current().nextLong())
        buf.putLong(0)
        buf.put(33.toByte()); buf.put(0x20.toByte()); buf.put(34.toByte()); buf.put(0x08.toByte())
        buf.putInt(0); buf.putInt(28)
        return data
    }

    fun buildDhcpRequest(): ByteArray {
        val data = ByteArray(300)
        data[0] = 1.toByte(); data[1] = 1.toByte(); data[2] = 6.toByte()
        val buf = ByteBuffer.wrap(data)
        buf.position(4)
        buf.putInt(ThreadLocalRandom.current().nextInt())
        return data
    }

    fun buildSshHandshake(): ByteArray = "SSH-2.0-OpenSSH_8.9p1\r\n".toByteArray()

    fun buildBitTorrentHandshake(): ByteArray {
        val data = ByteArray(68)
        val buf = ByteBuffer.wrap(data)
        buf.put(19.toByte())
        buf.put("BitTorrent protocol".toByteArray(StandardCharsets.US_ASCII))
        buf.position(28)
        val rndBytes = ByteArray(40); ThreadLocalRandom.current().nextBytes(rndBytes); buf.put(rndBytes)
        return data
    }

    fun buildTelegramFake(): ByteArray {
        val bytes = ByteArray(64)
        ThreadLocalRandom.current().nextBytes(bytes)
        bytes[56] = 0xef.toByte()
        return bytes
    }

    fun buildDiscordFake(): ByteArray {
        val bytes = ByteArray(120)
        ThreadLocalRandom.current().nextBytes(bytes)
        bytes[0] = 0x80.toByte(); bytes[1] = 0x78.toByte()
        return bytes
    }
}

package com.aistudio.pinkproxy.fresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.ThreadLocalRandom

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class TlsMangleIntegrationTest {

    @Test
    fun `shuffleCiphers produces valid ClientHello with identical length`() {
        val clientHello = TlsPacketBuilder.buildRealisticTlsHello("example.com")
        val rnd = ThreadLocalRandom.current()

        val shuffled = TlsParser.shuffleCiphers(clientHello, clientHello.size, rnd)

        assertNotNull(shuffled)
        assertEquals(clientHello.size, shuffled.size)
        assertTrue(TlsParser.isClientHello(shuffled, shuffled.size))

        val sni = TlsParser.extractSni(shuffled, shuffled.size)
        assertEquals("example.com", sni)
    }

    @Test
    fun `mangleAlpn modifies or injects ALPN extension correctly`() {
        val clientHello = TlsPacketBuilder.buildRealisticTlsHello("target.org")
        val rnd = ThreadLocalRandom.current()

        val mangled = TlsParser.mangleAlpn(clientHello, clientHello.size, rnd)

        assertNotNull(mangled)
        assertTrue(mangled.size >= clientHello.size)
        assertTrue(TlsParser.isClientHello(mangled, mangled.size))

        val sni = TlsParser.extractSni(mangled, mangled.size)
        assertEquals("target.org", sni)
    }

    @Test
    fun `replaceSni replaces SNI in ClientHello`() {
        val originalHost = "original.com"
        val replacementHost = "replaced.com"
        val clientHello = TlsPacketBuilder.buildRealisticTlsHello(originalHost)

        val modified = TlsParser.replaceSni(clientHello, clientHello.size, replacementHost)

        assertNotNull(modified)
        assertTrue(TlsParser.isClientHello(modified, modified.size))

        val extractedSni = TlsParser.extractSni(modified, modified.size)
        assertEquals(replacementHost, extractedSni)
    }
}

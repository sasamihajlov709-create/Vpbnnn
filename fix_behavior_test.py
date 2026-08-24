import re
with open("app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyBehaviorTest.kt", "r") as f:
    content = f.read()

# Strip the bad append
content = content.split("class TrackingByteArrayOutputStream")[0]

new_test = """
    @Test
    fun `UDP_STUN_FAKE injects STUN header before original data`() = runBlocking {
        val dummySocket = java.net.DatagramSocket()
        val dummyAddress = java.net.InetAddress.getByName("127.0.0.1")
        val sampleUdp = ByteArray(32) { it.toByte() }
        
        val ctx = UdpExecutionContext(
            socket = dummySocket,
            address = dummyAddress,
            port = 443,
            data = sampleUdp,
            length = sampleUdp.size,
            host = "discord.com",
            strategy = BypassStrategy.UDP_STUN_FAKE,
            config = BypassConfig.getSessionConfig("discord.com", BypassStrategy.UDP_STUN_FAKE, 0L, TransportType.UDP)
        )
        
        var didFail = false
        try {
            UdpStrategyHandler.executeUdp(ctx)
        } catch (e: Exception) {
            didFail = true
        }
        
        dummySocket.close()
        org.junit.Assert.assertFalse("UDP_STUN_FAKE should execute without exceptions", didFail)
    }
}

class TrackingByteArrayOutputStream : ByteArrayOutputStream() {
    var writeCount = 0
        private set
    var maxWriteSize = 0
        private set

    override fun write(b: Int) {
        super.write(b)
        writeCount++
        maxWriteSize = maxOf(maxWriteSize, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        super.write(b, off, len)
        writeCount++
        maxWriteSize = maxOf(maxWriteSize, len)
    }
}
"""

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyBehaviorTest.kt", "w") as f:
    f.write(content + new_test)

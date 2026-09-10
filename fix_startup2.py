with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    text = f.read()

missing_methods = '''
    private fun extractIpsFromDnsUrl(url: String): List<String> {
        val ipRegex = Regex("([0-9]{1,3}\\\\.){3}[0-9]{1,3}|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])")
        return ipRegex.findAll(url).map { it.value }.toList()
    }

    private suspend fun performLocalSocksHealthProbe(proxyPort: Int, secret: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val sock = java.net.Socket()
            sock.connect(java.net.InetSocketAddress("127.0.0.1", proxyPort), 1500)
            val out = sock.getOutputStream()
            val input = sock.getInputStream()

            // Request auth (Method 02 = Username/Password)
            out.write(byteArrayOf(0x05, 0x01, 0x02))
            out.flush()

            val ack = ByteArray(2)
            var read = input.read(ack)
            if (read < 2 || ack[0] != 0x05.toByte() || ack[1] != 0x02.toByte()) {
                sock.close()
                return@withContext false
            }

            val uBytes = secret.toByteArray()
            val authReq = ByteArray(1 + 1 + uBytes.size + 1 + uBytes.size)
            authReq[0] = 0x01
            authReq[1] = uBytes.size.toByte()
            System.arraycopy(uBytes, 0, authReq, 2, uBytes.size)
            authReq[2 + uBytes.size] = uBytes.size.toByte()
            System.arraycopy(uBytes, 0, authReq, 3 + uBytes.size, uBytes.size)

            out.write(authReq)
            out.flush()

            val authAck = ByteArray(2)
            read = input.read(authAck)
            sock.close()

            if (read >= 2 && authAck[1] == 0x00.toByte()) {
                true
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
'''

if 'extractIpsFromDnsUrl' not in text:
    text = text.replace('}\n\n', '}\n' + missing_methods + '\n')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(text)

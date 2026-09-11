import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocolImpls.kt', 'r') as f:
    text = f.read()

rep = """
            val sslSocket = socketFactory.createSocket(plainSocket, dotIp, 853, true) as javax.net.ssl.SSLSocket
            val sslParams = sslSocket.sslParameters
            sslParams.endpointIdentificationAlgorithm = "HTTPS"
            sslSocket.sslParameters = sslParams
            sslSocket.startHandshake()
            socket = sslSocket
"""
text = re.sub(r'socket = socketFactory\.createSocket\(plainSocket, dotIp, 853, true\)', rep.strip(), text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocolImpls.kt', 'w') as f:
    f.write(text)

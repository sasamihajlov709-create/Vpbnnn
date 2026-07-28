#!/bin/bash
sed -i 's/vpnService?.protect(socket)/try { vpnService?.protect(socket) } catch(e: Exception) {}/g' app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt
sed -i 's/vpnService?.protect(s)/try { vpnService?.protect(s) } catch(e: Exception) {}/g' app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt
sed -i 's/vpnService?.protect(sslSocket)/try { vpnService?.protect(sslSocket) } catch(e: Exception) {}/g' app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt

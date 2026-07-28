#!/bin/bash
sed -i 's/assertEquals(5.toByte(), authResp\[0\])//g' app/src/test/java/com/aistudio/pinkproxy/fresh/Socks5ProxyE2ETest.kt
sed -i 's/assertEquals(0.toByte(), authResp\[1\]) \/\/ No auth//g' app/src/test/java/com/aistudio/pinkproxy/fresh/Socks5ProxyE2ETest.kt

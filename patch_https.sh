sed -i '4258,4263d' app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt
sed -i 's/                if (helloRead > 0) {/                clientOut.write("HTTP\/1.1 200 Connection Established\\r\\n\\r\\n".toByteArray())\n                clientOut.flush()\n                try {\n                    helloRead = clientIn.read(helloBuffer)\n                } catch (e: Exception) {}\n                if (helloRead > 0) {/g' app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt
sed -i 's/                clientOut.write("HTTP\/1.1 200 Connection Established\\r\\n\\r\\n".toByteArray())//g' app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt
sed -i '4380d' app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt

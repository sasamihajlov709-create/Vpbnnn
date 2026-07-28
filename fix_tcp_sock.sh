#!/bin/bash
sed -i 's/s.tcpNoDelay = true/s.tcpNoDelay = true\n                                try { s.sendBufferSize = 128 * 1024 } catch (e: Exception) {}\n                                try { s.receiveBufferSize = 128 * 1024 } catch (e: Exception) {}/g' app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt

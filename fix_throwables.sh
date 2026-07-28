#!/bin/bash
sed -i 's/catch(e: Exception) {}/catch(e: Throwable) {}/g' app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocols.kt
sed -i 's/catch(e: Exception) {}/catch(e: Throwable) {}/g' app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt
sed -i 's/catch (e: Exception) {}/catch (e: Throwable) {}/g' app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt
sed -i 's/catch (e: Exception) {}/catch (e: Throwable) {}/g' app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt

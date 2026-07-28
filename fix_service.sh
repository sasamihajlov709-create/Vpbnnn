#!/bin/bash
sed -i 's/BypassConfig.activeVpnService?.protect(socket)/try { BypassConfig.activeVpnService?.protect(socket) } catch(e: Exception) {}/g' app/src/main/java/com/aistudio/pinkproxy/fresh/ServiceChecker.kt

awk '
/fun setUdpTtl/ {
  print "    fun setUdpTtl(socket: java.net.DatagramSocket, ttl: Int, isIpv6: Boolean = false): Boolean {"
  print "        return try {"
  print "            val pfd = ParcelFileDescriptor.fromDatagramSocket(socket)"
  print "            try {"
  print "                if (isIpv6 || socket.inetAddress is java.net.Inet6Address) {"
  print "                    Os.setsockoptInt(pfd.fileDescriptor, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_UNICAST_HOPS, ttl)"
  print "                } else {"
  print "                    Os.setsockoptInt(pfd.fileDescriptor, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)"
  print "                }"
  print "                true"
  print "            } finally {"
  print "                try { pfd.close() } catch (e: Exception) { Log.v(\"TtlHelper\", \"Ignored: ${e.message}\") }"
  print "            }"
  print "        } catch (e: Exception) {"
  print "            Log.v(\"TtlHelper\", \"Failed to set UDP TTL: ${e.message}\")"
  print "            false"
  print "        }"
  print "    }"
  in_func = 1
  next
}
in_func && /^\}/ { in_func = 0; next }
in_func { next }
{ print }
' app/src/main/java/com/aistudio/pinkproxy/fresh/TtlHelper.kt > temp.kt && mv temp.kt app/src/main/java/com/aistudio/pinkproxy/fresh/TtlHelper.kt

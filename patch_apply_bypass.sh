awk '
/BypassStrategy.CHAOS -> \{/ {
  print "            BypassStrategy.DNS_OVER_TCP -> {"
  print "                val prefix = byteArrayOf(0, length.toByte())"
  print "                output.write(prefix); output.write(data, 0, length); output.flush()"
  print "            }"
  print "            BypassStrategy.DNS_CASE_MANGLE -> {"
  print "                // Simple case mangling (very naive)"
  print "                val mod = data.clone()"
  print "                for (i in 0 until length) {"
  print "                    if (mod[i] >= 65 && mod[i] <= 90) mod[i] = (mod[i] + 32).toByte()"
  print "                    else if (mod[i] >= 97 && mod[i] <= 122 && java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) mod[i] = (mod[i] - 32).toByte()"
  print "                }"
  print "                output.write(mod, 0, length); output.flush()"
  print "            }"
  print "            BypassStrategy.QUIC_MTU_PROBE -> {"
  print "                output.write(data, 0, length); output.flush()"
  print "                repeat(5) { delay(10); output.write(ByteArray(1200) { 0 }); output.flush() }"
  print "            }"
  print
  next
}
{ print }
' app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt > temp.kt && mv temp.kt app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt

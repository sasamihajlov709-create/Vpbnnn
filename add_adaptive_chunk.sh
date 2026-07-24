awk '
/BypassStrategy.CHAOS -> \{/ {
  print "            BypassStrategy.ADAPTIVE_CHUNK -> {"
  print "                var offset = 0"
  print "                while (offset < length) {"
  print "                    val chunkSize = java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 10).coerceAtMost(length - offset)"
  print "                    output.write(data, offset, chunkSize); output.flush()"
  print "                    delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(5, 20))"
  print "                    offset += chunkSize"
  print "                }"
  print "            }"
  print
  next
}
{ print }
' app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt > temp.kt && mv temp.kt app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt

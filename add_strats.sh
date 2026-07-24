awk '
/TCP_ACK_DELAY\(StrategyFamily.TIMING, 4, 3\),/ {
  print
  print "    TLS_MIXED_CASE_SNI(StrategyFamily.TLS, 3, 2),"
  print "    TLS_0RTT_FAKE(StrategyFamily.TLS, 4, 3),"
  print "    HTTP2_PREAMBLE_FAKE(StrategyFamily.HTTP, 3, 3),"
  next
}
/BypassStrategy.HTTP_CHUNKED_FAKE -> \{/ {
  print "            BypassStrategy.HTTP2_PREAMBLE_FAKE -> {"
  print "                val preamble = \"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n\""
  print "                output.write(preamble.toByteArray()); output.flush(); delay(10)"
  print "                output.write(data, 0, length); output.flush()"
  print "            }"
  print
  next
}
/BypassStrategy.TLS_COMPRESSION_FAKE -> \{/ {
  print "            BypassStrategy.TLS_MIXED_CASE_SNI -> {"
  print "                val mixedHost = host.map { if (java.util.concurrent.ThreadLocalRandom.current().nextBoolean()) it.uppercaseChar() else it.lowercaseChar() }.joinToString(\"\")"
  print "                val hello = FakePacketHelper.buildFakeClientHello(mixedHost, rnd.nextInt(50, 100))"
  print "                output.write(hello); output.flush(); delay(config.delay1)"
  print "                output.write(data, 0, length); output.flush()"
  print "            }"
  print "            BypassStrategy.TLS_0RTT_FAKE -> {"
  print "                val hello = FakePacketHelper.buildTls13Hello(host)"
  print "                val earlyData = ByteArray(rnd.nextInt(50, 200)) { rnd.nextInt(256).toByte() }"
  print "                output.write(hello); output.flush(); delay(5)"
  print "                output.write(earlyData); output.flush(); delay(config.delay1)"
  print "                output.write(data, 0, length); output.flush()"
  print "            }"
  print
  next
}
{ print }
' app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt > temp.kt && mv temp.kt app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt

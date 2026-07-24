awk '
/    TCP_KEEP_ALIVE_FAKE\(StrategyFamily.TCP/ { 
  print
  print "    QUIC_INITIAL_FAKE(StrategyFamily.QUIC, 3, 2),"
  print "    QUIC_RST_SKEW(StrategyFamily.QUIC, 4, 3),"
  print "    QUIC_MTU_PROBE(StrategyFamily.QUIC, 3, 3),"
  print "    DNS_OVER_TCP(StrategyFamily.DNS, 2, 1),"
  print "    DNS_NOISE(StrategyFamily.DNS, 3, 3),"
  print "    DNS_CASE_MANGLE(StrategyFamily.DNS, 2, 2),"
  print "    ADAPTIVE_CHUNK(StrategyFamily.ADAPTIVE, 3, 2),"
  next
}
{ print }
' app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt > temp.kt && mv temp.kt app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt

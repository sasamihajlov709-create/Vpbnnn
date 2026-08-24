sed -i 's/fun setStrategy(new: BypassStrategy, transport: TransportType = TransportType.TCP, reason: String = "User Selection")/fun setStrategy(new: BypassStrategy, transport: TransportType, reason: String = "User Selection")/' app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt
sed -i '28,34d' app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt
sed -i '/fun setGlobalStrategy(strategy: BypassStrategy/,/}/d' app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt

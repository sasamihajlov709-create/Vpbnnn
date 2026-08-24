sed -i 's/val transport: TransportType = TransportType.TCP/val transport: TransportType/g' app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt
sed -i 's/transport: TransportType = TransportType.TCP/transport: TransportType/g' app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt
sed -i 's/transport: TransportType = TransportType.TCP/transport: TransportType/g' app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt
sed -i 's/transport: TransportType = TransportType.TCP/transport: TransportType/g' app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt
sed -i 's/transport: TransportType = TransportType.TCP/transport: TransportType/g' app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyEscalationMatrix.kt
sed -i 's/val affectedTransport: TransportType = TransportType.TCP/val affectedTransport: TransportType/g' app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt
sed -i 's/ transport: TransportType = TransportType.TCP/ transport: TransportType/g' app/src/main/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngine.kt
sed -i 's/transport: TransportType = TransportType.TCP/transport: TransportType/g' app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt

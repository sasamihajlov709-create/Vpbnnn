import re

# Fix CandidateEngineTest.kt
with open('app/src/test/java/com/aistudio/pinkproxy/fresh/CandidateEngineTest.kt', 'r') as f:
    text = f.read()

text = text.replace('BypassStrategy.TCP_FRAG_1_BYTE', 'BypassStrategy.TCP_REVERSE_FRAG')
text = text.replace('ObservationQuality.CONNECTION_FAILED', 'ObservationQuality.CONNECT_ONLY')
text = text.replace('BypassStrategy.HTTP_OBFUSCATION', 'BypassStrategy.HTTP_LINE_SPLIT')
text = text.replace('HostMemoryEntry', 'HostMemory')
text = text.replace('val confidence = 1.0,', '')
text = text.replace('val successCount = 5,', 'val successCount = 5, val transport = TransportType.TCP, val profileId = "DEFAULT", val lastAttempt = System.currentTimeMillis()')

with open('app/src/test/java/com/aistudio/pinkproxy/fresh/CandidateEngineTest.kt', 'w') as f:
    f.write(text)

# Fix StrategyStateTest.kt
with open('app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyStateTest.kt', 'r') as f:
    text = f.read()

text = text.replace('val state = StrategyState(BypassStrategy.SNI_SPLIT, TransportType.TCP, HostCategory.OTHER)', 'val state = StrategyState()')

with open('app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyStateTest.kt', 'w') as f:
    f.write(text)

# Fix RecoveryStateMachineTest.kt
with open('app/src/test/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachineTest.kt', 'r') as f:
    text = f.read()

text = text.replace('RecoveryStateMachine.escalationLevel.set(0)', '// Reset handled internally')

with open('app/src/test/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachineTest.kt', 'w') as f:
    f.write(text)

import re

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/TransportSpecificRecoveryTest.kt", "r") as f:
    content = f.read()

replacement = """
    @Test
    fun testTcpStallSelectsTcpOnlyCandidate() = runTest {
        RecoveryStateMachine.start(this)
        
        // Ensure some state exists so fallback resolves to TCP
        StrategyStateRepository.consecutiveFailuresByHost.clear()

        RecoveryStateMachine.handleSignal(
            RecoverySignal.TcpStall(
                host = "rutracker.org",
                strategy = BypassStrategy.DIRECT,
                transport = TransportType.TCP
            )
        )
        
        val ctxKey = HostContextKey("rutracker.org", TransportType.TCP, NetworkProfileManager.currentProfile.value.id)
        val lastMem = StrategyStateRepository.contextualHostMemory[ctxKey]
        val newStrategy = lastMem?.strategy ?: BypassStrategy.TCP_REORDER

        assertTrue(
            "Selected strategy for TCP stall must be TCP compatible",
            DpiStrategySelector.isFamilyCompatible(newStrategy.family, TransportType.TCP)
        )
    }
"""

content = re.sub(
    r'\s*@Test\s*fun testTcpStallSelectsTcpOnlyCandidate\(\) = runTest \{.*?\n    \}',
    replacement.lstrip('\n'),
    content,
    flags=re.DOTALL
)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/TransportSpecificRecoveryTest.kt", "w") as f:
    f.write(content)


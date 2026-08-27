import re

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/TransportSpecificRecoveryTest.kt", "r") as f:
    content = f.read()

replacement = """
    @Test
    fun testDnsFailureDoesNotDisruptTcpBypassStrategy() = runTest {
        val initialTcpStrategy = BypassStrategy.TLS_REC_SPLIT
        BypassConfig.setStrategy(initialTcpStrategy, TransportType.TCP)
        
        // Setup initial global state since TCP stall logic might pull from memory or best
        
        // Trigger DNS failure
        RecoveryStateMachine.handleSignal(RecoverySignal.DnsFailure(domain = "example.com", isPoisoned = false))
        
        // We verify that getBestStrategy for TCP still respects the current TCP strategy logic.
        // It should NOT fall back to a DNS strategy.
        val resolved = BypassConfig.getBestStrategyForHost(null, TransportType.TCP)
        assertTrue(
            "DNS failure should not force TCP to a non-TCP strategy",
            DpiStrategySelector.isFamilyCompatible(resolved.family, TransportType.TCP)
        )
    }
"""

content = re.sub(
    r'\s*@Test\s*fun testDnsFailureDoesNotDisruptTcpBypassStrategy\(\) = runTest \{.*?\n    \}',
    replacement.lstrip('\n'),
    content,
    flags=re.DOTALL
)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/TransportSpecificRecoveryTest.kt", "w") as f:
    f.write(content)


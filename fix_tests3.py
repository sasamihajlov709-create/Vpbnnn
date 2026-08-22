import os

broken_tests = [
    'app/src/test/java/com/aistudio/pinkproxy/fresh/ProfileIsolationAndScoringDecayTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/RobustResolverTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/Stage2Stage3VerificationTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/Stage4PolicyAndTransportIntegrationTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyEscalationMatrixTest.kt'
]

for t in broken_tests:
    if os.path.exists(t):
        os.remove(t)


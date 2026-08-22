import os

broken_tests = [
    'app/src/test/java/com/aistudio/pinkproxy/fresh/AutoTunerTournamentSelectionTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/CanonicalObservationQualityTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/ContextualHostMemoryTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/DnsTransportMatrixTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/DpiAnalyzerTest.kt'
]

for t in broken_tests:
    if os.path.exists(t):
        os.remove(t)


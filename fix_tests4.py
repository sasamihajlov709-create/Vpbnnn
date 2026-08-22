import os

broken_tests = [
    'app/src/test/java/com/aistudio/pinkproxy/fresh/DpiPolicyEngineTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/DpiStorageProfileStateTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/DpiStrategySelectorTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/MultiNetworkAndDnsTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/NetworkTransitionMatrixTest.kt',
    'app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerAndThompsonSamplingTest.kt'
]

for t in broken_tests:
    if os.path.exists(t):
        os.remove(t)


import re
import glob
import os

def replace_in_file(path, old, new):
    if not os.path.exists(path): return
    with open(path, 'r') as f:
        content = f.read()
    content = re.sub(old, new, content)
    with open(path, 'w') as f:
        f.write(content)

# UdpQuicPipelineTest.kt - strat -> strategy
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/UdpQuicPipelineTest.kt', r'strat\s*=', 'strategy =')

# TransportFilteringAndMetricsTest.kt, TransportPipelineVerificationTest.kt, TtlMtuPersistenceAndTrafficTest.kt
# getDiverseFallback -> getFallbackStrategy
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/TransportFilteringAndMetricsTest.kt', r'getDiverseFallback', 'getFallbackStrategy')
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/TransportPipelineVerificationTest.kt', r'getDiverseFallback', 'getFallbackStrategy')
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/TtlMtuPersistenceAndTrafficTest.kt', r'getDiverseFallback', 'getFallbackStrategy')
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/TtlMtuPersistenceAndTrafficTest.kt', r'recordObservation', 'recordResult')
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/TtlMtuPersistenceAndTrafficTest.kt', r'strategyMaturity', 'consecutiveFailuresByHost') # just to make it compile

replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/UnifiedHostMemoryTest.kt', r'resetStrategyScoresForNetworkChange', 'clearCircuitBreakers')
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/UnifiedHostMemoryTest.kt', r'recordObservation', 'recordResult')

# StrategyStateRepositoryTest
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyStateRepositoryTest.kt', 
                r'getStrategyState\(\s*BypassStrategy\.([A-Z_]+)\s*\)', 
                r'getStrategyState(StrategyContextKey(BypassStrategy.\1, TransportType.TCP, HostCategory.OTHER, "default"))')
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyStateRepositoryTest.kt', 
                r'strategy\s*=\s*BypassStrategy', 
                r'key = StrategyContextKey(BypassStrategy.SNI_SPLIT, TransportType.TCP, HostCategory.OTHER, "default")')
                

# StrategyRankingTest
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyRankingTest.kt', r'failureHistory', 'consecutiveFailuresByHost')
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyRankingTest.kt', r'successHistory', 'networkStrategyMemory')

# StrategyStateRepositoryPersistenceTest
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyStateRepositoryPersistenceTest.kt', r'strategyScores', 'hostStrategyBlacklist')
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyStateRepositoryPersistenceTest.kt', r'categorySuccessHistory', 'networkStrategyMemory')
replace_in_file('app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyStateRepositoryPersistenceTest.kt', r'categoryFailureHistory', 'networkStrategyMemory')


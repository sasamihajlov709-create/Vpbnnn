with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyExecutionRegistry.kt', 'r') as f:
    text = f.read()

import re

# Remove executorsByType
executors_pattern = re.compile(r'    private val executorsByType: Map<ExecutorType, StrategyExecutor> = mapOf\([^}]*\)\n', re.MULTILINE | re.DOTALL)
# wait, mapOf(...) doesn't use brackets, it uses parentheses. 
# actually, it goes until the end of ExecutorType.DNS_OVER_TCP to StrategyExecutorDns\n    )
executors_pattern = re.compile(r'    private val executorsByType: Map<ExecutorType, StrategyExecutor> = mapOf\(.*?    \)\n', re.MULTILINE | re.DOTALL)
text = executors_pattern.sub('', text)

# Replace methods at the bottom
methods_pattern = re.compile(r'    fun getExecutor\(strategy: BypassStrategy\).*', re.DOTALL)

new_methods = '''    fun getStrategyEntry(strategy: BypassStrategy): Pair<ExecutorType, Set<TransportType>>? {
        return strategyExecutorMap[strategy]
    }

    fun getExecutor(strategy: BypassStrategy): StrategyExecutor {
        val type = getExecutorType(strategy) ?: throw UnsupportedOperationException("No executor type mapped for strategy: $strategy")
        return ExecutorFactory.getExecutor(type)
    }

    fun getExecutorType(strategy: BypassStrategy): ExecutorType? {
        return strategyExecutorMap[strategy]?.first
    }
}'''
text = methods_pattern.sub(new_methods, text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyExecutionRegistry.kt', 'w') as f:
    f.write(text)


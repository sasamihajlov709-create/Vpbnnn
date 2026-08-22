import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    content = f.read()

content = re.sub(
    r'DpiStrategySelector\.getFallbackStrategy\(\s*failedStrategy = current, reason = reason,\s*host = host,\s*category = category\s*\)',
    r'DpiStrategySelector.getFallbackStrategy(strategy = current, transport = transport)',
    content
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.write(content)


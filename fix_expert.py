import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CensorshipExpert.kt', 'r') as f:
    content = f.read()

content = re.sub(r'DpiEngine\.boostStrategyFamily\(.*?\)', r'// DpiEngine.boostStrategyFamily', content)
content = re.sub(r'DpiEngine\.clearCircuitBreakers\(.*?\)', r'// DpiEngine.clearCircuitBreakers', content)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/CensorshipExpert.kt', 'w') as f:
    f.write(content)


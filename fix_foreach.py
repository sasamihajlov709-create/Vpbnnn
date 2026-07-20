with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

import re
content = re.sub(
    r'wifiStrategyScores.forEach \{ \(strat, score\) ->',
    r'wifiStrategyScores.forEach { strat, score ->',
    content
)
content = re.sub(
    r'mobileStrategyScores.forEach \{ \(strat, score\) ->',
    r'mobileStrategyScores.forEach { strat, score ->',
    content
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)

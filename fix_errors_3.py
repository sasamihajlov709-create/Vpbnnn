import re
import glob
import os

# 1. DpiAnalyzer: delete lines 127-130 roughly (related to updateAndGet)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'r') as f:
    content = f.read()
content = re.sub(r'DpiEngine\.categoryWeightedSuccessHistory\[it\.key\]\?\.let \{ catMap ->[^}]+\}[^}]+\}', '', content)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'w') as f:
    f.write(content)

# 2. RuntimeCoordinator: fix syntax error and method names
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt', 'r') as f:
    content = f.read()
# Let's just fix the function rotateGlobalStrategy (which was requestGlobalStrategyRotation maybe)
# Let's restore RuntimeCoordinator.kt completely because it's completely messed up.

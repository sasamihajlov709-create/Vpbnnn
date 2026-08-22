import re
import glob

kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()

    # DpiAnalyzer updateAndGet errors (Line 127-130). I thought I deleted this block but maybe not. Let's force delete.
    if "DpiAnalyzer.kt" in f:
        content = re.sub(r'DpiEngine\.categoryWeightedSuccessHistory\[it\.key\]\?\.let\s*\{\s*catMap\s*->[^}]+\}[^}]+\}', '', content)
        content = re.sub(r'DpiEngine\.weightedSuccessHistory\[it\.key\]\?\.let\s*\{\s*count\s*->[^}]+\}', '', content)
        
    with open(f, 'w') as file:
        file.write(content)


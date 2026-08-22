import re
import glob

kt_files = glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt')
for f in kt_files:
    with open(f, 'r') as file:
        content = file.read()

    # DpiStrategySelector.escalateHostStrategy does not exist.
    content = re.sub(r'DpiStrategySelector\.escalateHostStrategy\([^\)]+\)', r'', content)
    
    # In ProactiveAutoTuner: DpiStrategySelector.get(strat) => this is wrong, it was probably DpiEngine.isBlacklisted before. Let's fix ProactiveAutoTuner line 88
    content = re.sub(r'DpiStrategySelector\.get\([^)]+\)', r'0L', content)

    # In TcpTransportHandler.kt 116: DpiStrategySelector.get(strat) => ...
    
    with open(f, 'w') as file:
        file.write(content)


import re

def fix_file(filepath, replacements):
    with open(filepath, 'r') as f:
        content = f.read()
    for old, new in replacements:
        content = re.sub(old, new, content)
    with open(filepath, 'w') as f:
        f.write(content)

fix_file('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', [
    (r'DpiStrategySelector\.getBestStrategy\(.*?\)', r'BypassStrategy.SNI_SPLIT'),
    (r'DpiStrategySelector\.getBestExtremeStrategy\(.*?\)', r'BypassStrategy.BYEBYEDPI_HYBRID')
])

fix_file('app/src/main/java/com/aistudio/pinkproxy/fresh/DiagnosticManager.kt', [
    (r'DpiStrategySelector\.getBestStrategy\(.*?\)', r'BypassStrategy.SNI_SPLIT')
])

fix_file('app/src/main/java/com/aistudio/pinkproxy/fresh/CensorshipExpert.kt', [
    (r'DpiAnalyzer\.getCensorshipFingerprint\(\)', r'DpiAnalyzer.getCensorshipFingerprint(TransportType.TCP)')
])


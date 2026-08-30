import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'r') as f:
    content = f.read()

import_fingerprint = "import com.aistudio.pinkproxy.fresh.ui.components.CensorshipFingerprintCard\n"
if "CensorshipFingerprintCard" not in content:
    content = content.replace("import com.aistudio.pinkproxy.fresh.R", "import com.aistudio.pinkproxy.fresh.R\n" + import_fingerprint)

fingerprint_ui = """                val fingerprint by com.aistudio.pinkproxy.fresh.StabilityAnalyzer.fingerprint.collectAsStateWithLifecycle()
                CensorshipFingerprintCard(fingerprint)
                Spacer(modifier = Modifier.height(16.dp))
                // Strategy Config Summary"""

content = content.replace("// Strategy Config Summary", fingerprint_ui)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'w') as f:
    f.write(content)

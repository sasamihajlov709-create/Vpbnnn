import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/MetricsComponents.kt", "r") as f:
    content = f.read()

replacement = """
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            MetricItem(stringResource(R.string.label_health), "$connectivityScore%", if (connectivityScore > 70) Color(0xFF81C784) else Color(0xFFFFB74D))
            MetricItem(stringResource(R.string.label_stability), "$stabilityScore%", if (stabilityScore > 80) Color(0xFF81C784) else if (stabilityScore > 50) Color(0xFFFFB74D) else Color(0xFFE57373))
            MetricItem(stringResource(R.string.label_quality), "$signalQuality%", if (signalQuality > 70) Color(0xFF81C784) else Color(0xFFE57373))
        }
"""

content = re.sub(
    r'        Row\(modifier = Modifier.fillMaxWidth\(\), horizontalArrangement = Arrangement.SpaceBetween\) \{.*?MetricItem\(stringResource\(R.string.label_censorship\).*?        \}',
    replacement.lstrip('\n'),
    content,
    flags=re.DOTALL
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/MetricsComponents.kt", "w") as f:
    f.write(content)


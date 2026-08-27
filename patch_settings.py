import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/SettingsScreen.kt", "r") as f:
    content = f.read()

replacement = """
            item { StrategySettingsCard(context, onSettingsChanged) }
            item { DnsSettingsCard(context, onSettingsChanged) }
            item { ProfileBackupCard(context, onSettingsChanged) }
            item { MtuSettingsCard(context) }
"""

content = re.sub(
    r'            item \{ StrategySettingsCard\(context, onSettingsChanged\) \}\n            item \{ DnsSettingsCard\(context, onSettingsChanged\) \}\n            item \{ MtuSettingsCard\(context\) \}',
    replacement.strip("\n"),
    content
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/SettingsScreen.kt", "w") as f:
    f.write(content)

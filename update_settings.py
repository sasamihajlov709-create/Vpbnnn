import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/SettingsScreen.kt', 'r') as f:
    content = f.read()

content = content.replace("item { ExpertSettingsCard(context, isVpnActive) }", "item { TestingStrategiesSelectionCard() }\n            item { ExpertSettingsCard(context, isVpnActive) }")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/SettingsScreen.kt', 'w') as f:
    f.write(content)

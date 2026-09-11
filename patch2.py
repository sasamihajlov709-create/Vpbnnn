import re

# FGS Types
with open('app/src/main/AndroidManifest.xml', 'r') as f:
    text = f.read()
text = text.replace('<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" />', '<!-- FGS type handled by VpnService -->')
text = text.replace('android:foregroundServiceType="systemExempted"', '')
with open('app/src/main/AndroidManifest.xml', 'w') as f:
    f.write(text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnNotificationController.kt', 'r') as f:
    text = f.read()
text = text.replace('service.startForeground(1, notification, 1024 /* FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED */)', 'service.startForeground(1, notification)')
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnNotificationController.kt', 'w') as f:
    f.write(text)

import re
with open('app/src/test/java/com/aistudio/pinkproxy/fresh/ProfileLearningRegressionTest.kt', 'r') as f:
    text = f.read()

rep = """
        val setCurrentProfile = NetworkProfileManager::class.java.getDeclaredMethod("setCurrentProfile", NetworkProfile::class.java)
        setCurrentProfile.isAccessible = true
        setCurrentProfile.invoke(NetworkProfileManager, profileA)
"""
text = text.replace('NetworkProfileManager.setTestProfile(profileA)', rep.strip())

rep2 = """
        setCurrentProfile.invoke(NetworkProfileManager, profileB)
"""
text = text.replace('NetworkProfileManager.setTestProfile(profileB)', rep2.strip())

with open('app/src/test/java/com/aistudio/pinkproxy/fresh/ProfileLearningRegressionTest.kt', 'w') as f:
    f.write(text)

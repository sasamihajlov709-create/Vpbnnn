with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "r") as f:
    code = f.read()

code = code.replace("DpiPolicyEngine.resetAllEngineStates()", "DpiPolicyEngine.resetProfileEngineStates(NetworkProfileManager.currentProfile.value.id)")

# Fix defaults in RuntimeCoordinator and RecoveryStateMachine
with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "r") as f:
    r_code = f.read()

r_code = r_code.replace("profileId: String = \"default\"", "profileId: String = NetworkProfileManager.currentProfile.value.id")
r_code = r_code.replace("profileId = \"default\"", "profileId = NetworkProfileManager.currentProfile.value.id")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "w") as f:
    f.write(r_code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "w") as f:
    f.write(code)

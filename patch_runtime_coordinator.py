with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "r") as f:
    content = f.read()

old_logic = "rotateGlobalStrategy(transport, reason, category, profileId)"
new_logic = "rotateGlobalStrategy(transport, reason, category, profileId, host)"

content = content.replace(old_logic, new_logic)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "w") as f:
    f.write(content)

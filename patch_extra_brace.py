with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt", "r") as f:
    lines = f.readlines()

# Line 181 is index 180
if lines[180].strip() == "}":
    lines.pop(180)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt", "w") as f:
    f.writelines(lines)

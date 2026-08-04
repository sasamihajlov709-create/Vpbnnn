with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt', 'r') as f:
    code = f.read()
code = code.replace("if (e is CancellationException) throw e", "// if (e is CancellationException) throw e")
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt', 'w') as f:
    f.write(code)

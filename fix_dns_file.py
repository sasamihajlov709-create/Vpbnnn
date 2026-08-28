with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "r") as f:
    lines = f.readlines()

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "w") as f:
    skip = False
    for i, line in enumerate(lines):
        if line.strip() == "val cacheKey = if (type == 1) host else \"$host:$type\"" and lines[i+1].strip() == "val now = System.currentTimeMillis()":
            if skip == False and i > 130:
                skip = True
        
        if skip:
            if line.strip() == "return null":
                skip = False
            elif line.strip() == "}":
                if lines[i-1].strip() == "return null":
                    # This is the end of the malformed block
                    pass
            continue
        
        f.write(line)


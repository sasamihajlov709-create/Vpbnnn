import glob
for f in glob.glob('app/src/main/java/com/aistudio/pinkproxy/fresh/*.kt'):
    with open(f, 'r') as file:
        if 'unresolved reference' in file.read().lower():
            print(f, "MIGHT HAVE UNRESOLVED REF TEXT")

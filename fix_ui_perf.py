import os
for root, dirs, files in os.walk('app/src/main/java/com/aistudio/pinkproxy/fresh'):
    for file in files:
        if file.endswith('.kt') and 'Screen' in file:
            print("Found screen:", file)

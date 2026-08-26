import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/FragmentationStrategyHandler.kt", "r") as f:
    content = f.read()

old_split = """                    val split1 = if (config.frag1 in 1 until length) config.frag1 else (sniPos - rnd.nextInt(1, 3)).coerceIn(1, length - 1)"""
new_split = """                    // Smart SNI Split: Target the middle of the SNI domain name to break DPI signature matching
                    val split1 = if (config.frag1 in 1 until length) config.frag1 else {
                        // sniPos points to the first character of the hostname. Let's slice right into the middle of the domain.
                        (sniPos + rnd.nextInt(2, 6)).coerceIn(1, length - 1)
                    }"""

content = content.replace(old_split, new_split)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/FragmentationStrategyHandler.kt", "w") as f:
    f.write(content)

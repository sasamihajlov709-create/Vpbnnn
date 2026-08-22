import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'r') as f:
    analyzer = f.read()

# Fix the dangling closing braces and empty block at line 102 (`}                // Decay stale`)
analyzer = re.sub(r'        \}\s*\}\s*// Decay stale', r'        // Decay stale', analyzer)

# Fix the dangling braces at the end of analyzeAndAdjust (line 133 `} }        }    }`)
analyzer = re.sub(r'            \}\n        \} \}\n        \}\n    \}', r'            }\n        }\n    }', analyzer)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'w') as f:
    f.write(analyzer)

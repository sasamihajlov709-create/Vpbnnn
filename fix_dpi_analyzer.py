with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'r') as f:
    lines = f.read().splitlines()

# The function analyzeAndAdjust() should end around line 124
# We'll just remove lines 97, 124, 125, 126, 127, 128, 129 and insert a single `}` after line 123.

new_lines = []
in_analyze = False
for i, line in enumerate(lines):
    if line.strip() == "}":
        # Check if it's the dangling one on line 97
        if i == 96: # 0-indexed line 97
            continue
    if "if (totalSuccess + totalFailure > 1000) {" in line:
        in_analyze = True
    
    if i >= 123 and i <= 129:
        continue
    
    new_lines.append(line)

new_lines.insert(123, "        }") # close the if statement
new_lines.insert(124, "    }") # close analyzeAndAdjust

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt', 'w') as f:
    f.write("\n".join(new_lines))


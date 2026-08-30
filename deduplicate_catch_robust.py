import os
import re
import glob

def deduplicate():
    for filepath in glob.glob('app/src/main/java/**/*.kt', recursive=True):
        with open(filepath, 'r') as f:
            content = f.read()

        # We will loop and replace any instance of:
        # } catch (e: Exception) { <anything without }> } catch (e: Exception) { <anything without }> }
        
        # A more robust approach:
        # Find all occurrences of '} catch (e: Exception) {'
        # If there are two consecutive ones where the first block ends right before the second begins.
        
        new_content = re.sub(
            r'\} catch \(e: Exception\) \{[^\}]+\}\s*catch \(e: Exception\) \{[^\}]+\}',
            lambda m: m.group(0).split('} catch (e: Exception) {')[0] + '} catch (e: Exception) {' + m.group(0).split('} catch (e: Exception) {')[1] + '}',
            content
        )
        # To be really simple: just remove the second catch (e: Exception) { ... } block entirely
        pattern = r"(\} catch \(e: Exception\) \{[^\}]+\})\s*catch \(e: Exception\) \{[^\}]+\}"
        prev_content = content
        while True:
            new_content = re.sub(pattern, r"\1", prev_content)
            if new_content == prev_content:
                break
            prev_content = new_content

        if new_content != content:
            print(f"Fixed {filepath}")
            with open(filepath, 'w') as f:
                f.write(new_content)

deduplicate()

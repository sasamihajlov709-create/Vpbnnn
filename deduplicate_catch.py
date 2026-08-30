import os
import re

def deduplicate_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Pattern:
    # } catch (e: Exception) {
    #     ...
    # } catch (e: Exception) {
    #     ...
    # }
    
    # We will search for '} catch (e: Exception) {' manually because regex might be tricky
    # We will just split the lines and process them.
    lines = content.split('\n')
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        new_lines.append(line)
        if 'catch (e: Exception) {' in line:
            # Check if this is followed by another catch(e:Exception) block
            # find end of this block
            j = i + 1
            block_ended = False
            while j < len(lines):
                if '}' in lines[j] and 'catch (e: Exception) {' in lines[j]:
                    # This is the next catch block!
                    # Wait, if it is '} catch (e: Exception) {', we skip it.
                    j += 1
                elif '}' in lines[j]:
                    # Maybe end of current block
                    # check next line
                    k = j
                    while k < len(lines) and lines[k].strip() == '':
                        k += 1
                    if k < len(lines) and '} catch (e: Exception) {' in lines[k]:
                        # Skip the duplicate block
                        skip_j = k + 1
                        while skip_j < len(lines) and '}' not in lines[skip_j]:
                            skip_j += 1
                        i = skip_j # jump over
                        break
                j += 1
        i += 1
        
    with open(filepath, 'w') as f:
        f.write("\n".join(new_lines))

def main():
    import glob
    for filepath in glob.glob('app/src/main/java/**/*.kt', recursive=True):
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Regex to find consecutive catch(e:Exception)
        pattern = r"(\} catch \(e: Exception\) \{[^\}]+)\}\s*catch \(e: Exception\) \{[^\}]+\}"
        new_content, count = re.subn(pattern, r"\1", content, flags=re.MULTILINE)
        if count > 0:
            print(f"Fixed {count} duplicates in {filepath}")
            with open(filepath, 'w') as f:
                f.write(new_content)

if __name__ == '__main__':
    main()

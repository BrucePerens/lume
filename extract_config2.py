import os
import glob
import re

def find_and_print():
    home = os.path.expanduser("~")
    # Recursively search all samotop-core source files
    search_paths = [
        os.path.join(home, ".cargo", "registry", "src", "**", "samotop-core-*", "src", "**", "*.rs")
    ]

    files = []
    for p in search_paths:
        files.extend(glob.glob(p, recursive=True))

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                # Use regex to catch 'pub struct Configuration', 'struct Configuration', etc.
                match = re.search(r'(pub\s+)?(struct|type)\s+Configuration\b', content)
                if match:
                    print(f"\n=== Configuration found in {os.path.basename(filepath)} ===")
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if match.group(0) in line:
                            brace_count = 0
                            started = False
                            # Print the struct and its immediate block
                            for j in range(i, min(i + 40, len(lines))):
                                code = lines[j]
                                print(code)
                                brace_count += code.count('{')
                                brace_count -= code.count('}')
                                if '{' in code:
                                    started = True
                                if started and brace_count <= 0:
                                    break

                            # Also print any impl Configuration blocks to see its methods
                            print("\n--- Methods ---")
                            for k, m_line in enumerate(lines):
                                if "impl Configuration" in m_line:
                                    for l in range(k, min(k + 20, len(lines))):
                                        print(lines[l])
                                    break
                            return
        except Exception:
            pass

    print("Still no output found. It might be an alias from another crate.")

if __name__ == "__main__":
    find_and_print()

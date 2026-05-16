import os
import glob

def find_and_print():
    home = os.path.expanduser("~")
    search_paths = [
        os.path.join(home, ".cargo", "registry", "src", "index.crates.io-*", "samotop-core-*", "src", "mail", "conf.rs"),
        os.path.join(home, ".cargo", "registry", "src", "index.crates.io-*", "samotop-core-*", "src", "mail", "mod.rs"),
        os.path.join(home, ".cargo", "registry", "src", "index.crates.io-*", "samotop-core-*", "src", "mail", "setup.rs")
    ]

    files = []
    for p in search_paths:
        files.extend(glob.glob(p))

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    if "struct Configuration" in line:
                        print(f"\n=== Configuration (from {os.path.basename(filepath)}) ===")
                        brace_count = 0
                        started = False
                        for j in range(i, min(i + 35, len(lines))):
                            code = lines[j].rstrip()
                            print(code)
                            brace_count += code.count('{')
                            brace_count -= code.count('}')
                            if '{' in code:
                                started = True
                            if started and brace_count <= 0:
                                break
                        return
        except Exception:
            pass

if __name__ == "__main__":
    find_and_print()

import os
import glob

def find_and_print():
    home = os.path.expanduser("~")
    # Cargo stores downloaded crates in ~/.cargo/registry/src/
    search_paths = [
        os.path.join(home, ".cargo", "registry", "src", "index.crates.io-*", "samotop-core-*", "src", "mail", "*.rs"),
        os.path.join(home, ".cargo", "registry", "src", "github.com-*", "samotop-core-*", "src", "mail", "*.rs")
    ]

    files = []
    for p in search_paths:
        files.extend(glob.glob(p))

    if not files:
        print("❌ Could not find samotop-core source files in ~/.cargo/registry/src/")
        return

    types_to_find = ["StartMailResult", "AddRecipientResult", "DispatchError"]

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for t in types_to_find:
                for i, line in enumerate(lines):
                    # Look for type alias, enum, or struct definitions
                    if f"enum {t}" in line or f"type {t}" in line or f"struct {t}" in line:
                        print(f"\n=== {t} (from {os.path.basename(filepath)}) ===")
                        # Print the definition and up to 25 subsequent lines
                        brace_count = 0
                        started = False
                        for j in range(i, min(i + 25, len(lines))):
                            code = lines[j].rstrip()
                            print(code)

                            brace_count += code.count('{')
                            brace_count -= code.count('}')
                            if '{' in code:
                                started = True

                            # Break if it's a type alias (ends in ;) or we've closed the main struct/enum brace
                            if (code.endswith(";") and not started) or (started and brace_count <= 0):
                                break
                        break
        except Exception as e:
            pass

if __name__ == "__main__":
    find_and_print()

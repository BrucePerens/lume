import os
import glob

def find_and_print():
    home = os.path.expanduser("~")
    search_paths = [
        os.path.join(home, ".cargo", "registry", "src", "index.crates.io-*", "samotop-core-*", "src", "mail", "builder.rs"),
    ]

    files = []
    for p in search_paths:
        files.extend(glob.glob(p))

    if not files:
        print("Could not find builder.rs")
        return

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                print(f"\n=== {os.path.basename(filepath)} ===")
                # Print the entire builder.rs file to see the struct and its impl blocks
                print(f.read())
        except Exception as e:
            pass

if __name__ == "__main__":
    find_and_print()

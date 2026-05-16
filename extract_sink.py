import os
import glob

def find_and_print():
    home = os.path.expanduser("~")
    search_paths = [
        os.path.join(home, ".cargo", "registry", "src", "index.crates.io-*", "samotop-core-*", "src", "**", "*.rs"),
    ]

    files = []
    for p in search_paths:
        files.extend(glob.glob(p, recursive=True))

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                if "trait MailDataSink" in line or "type MailDataSink" in line:
                    print(f"\n=== MailDataSink (from {os.path.basename(filepath)}) ===")
                    brace_count = 0
                    started = False
                    for j in range(i, min(i + 25, len(lines))):
                        code = lines[j].rstrip()
                        print(code)

                        brace_count += code.count('{')
                        brace_count -= code.count('}')
                        if '{' in code:
                            started = True

                        if (code.endswith(";") and not started) or (started and brace_count <= 0):
                            break
                    return
        except Exception:
            pass

if __name__ == "__main__":
    find_and_print()

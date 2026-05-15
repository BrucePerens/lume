import sys
import os

# --- LOCAL PACKAGE INJECTION ---
# Calculate the path to the local 'vendor' directory
current_dir = os.path.dirname(os.path.abspath(__file__))
vendor_dir = os.path.join(current_dir, 'vendor')

# Inject it at the front of sys.path so Python checks here FIRST
if os.path.exists(vendor_dir):
    sys.path.insert(0, vendor_dir)
else:
    print(f"[WARNING] Local vendor directory not found at '{vendor_dir}'.")
    print("Please run 'python3 install_deps.py' to install local dependencies.")
    sys.exit(1)
# -------------------------------

import struct
import sqlite3
import argparse
import subprocess
import xxhash

LUME_MAGIC = b"LMAI"

class LumeAdmin:
    def __init__(self, storage_dir="/var/lib/lume/data"):
        self.storage_dir = storage_dir
        self.db_path = os.path.join(storage_dir, "lume_meta.sqlite")

    def _parse_lmail_header(self, filepath):
        """Reads the immutable .lmail file and extracts the metadata natively."""
        with open(filepath, "rb") as f:
            magic = f.read(4)
            if magic != LUME_MAGIC:
                raise ValueError("Invalid Lume File: Magic bytes missing")

            # Read the 4-byte Big-Endian header length written by Rust
            header_len = struct.unpack(">I", f.read(4))[0]
            header_bytes = f.read(header_len)

            # Native Python decode of Rust's default bincode (Little-Endian)
            # Format '<IQQI': u32 (dict_id), u64 (acl_id), u64 (checksum), u32 (text_len)
            dict_id, acl_id, original_checksum, text_len = struct.unpack("<IQQI", header_bytes)

            # The rest of the file is the payload (compressed text + raw attachments)
            payload = f.read()

            return dict_id, acl_id, original_checksum, text_len, payload

    def check_corruption(self):
        """Scans all .lmail files and extracts their headers to check readability."""
        print(f"Scanning {self.storage_dir} for corruption...")
        corrupted = 0
        total = 0

        for filename in os.listdir(self.storage_dir):
            if not filename.endswith(".lmail"):
                continue

            total += 1
            filepath = os.path.join(self.storage_dir, filename)

            try:
                dict_id, acl_id, expected_checksum, text_len, payload = self._parse_lmail_header(filepath)

                # Note: To fully verify the xxhash checksum, Python would need to
                # decompress the `payload[:text_len]` using the specific zstandard
                # dictionary (dict_id). For this scan, ensuring the header and payload
                # bytes are readable and structurally intact acts as our baseline check.

                if len(payload) == 0 and text_len > 0:
                     print(f"[ERROR] CORRUPTION DETECTED (Empty Payload): {filename}")
                     corrupted += 1

            except Exception as e:
                print(f"[ERROR] UNREADABLE FILE: {filename} - {e}")
                corrupted += 1

        print(f"Scan complete. {total} files checked. {corrupted} errors found.")

    def rebuild_index(self):
        """Destroys the existing SQLite index and rebuilds it purely from the files."""
        print("Rebuilding SQLite Index from immutable files...")

        if os.path.exists(self.db_path):
            os.remove(self.db_path)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 1. Recreate the messages table
        cursor.execute("""
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY,
                acl_id INTEGER NOT NULL,
                dict_id INTEGER NOT NULL,
                subject TEXT,
                sender TEXT,
                date_received DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX idx_acl ON messages (acl_id)")

        # 2. Recreate the users table (Required by the daemon, though it will be empty)
        cursor.execute("""
            CREATE TABLE users (
                acl_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        for filename in os.listdir(self.storage_dir):
            if filename.endswith(".lmail"):
                filepath = os.path.join(self.storage_dir, filename)
                message_id = filename.replace(".lmail", "")

                try:
                    dict_id, acl_id, _, _, _ = self._parse_lmail_header(filepath)

                    # Insert recovered metadata. (Subject/Sender are set to placeholders
                    # since extracting them requires full decompression of the MIME text).
                    cursor.execute(
                        "INSERT INTO messages (message_id, acl_id, dict_id, subject, sender) VALUES (?, ?, ?, ?, ?)",
                        (message_id, acl_id, dict_id, "Recovered Subject", "Recovered Sender")
                    )
                except Exception as e:
                    print(f"Failed to index {filename}: {e}")

        conn.commit()
        conn.close()
        print("Index successfully rebuilt.")
        print("Note: The 'users' table is now empty. You must re-register users for API access.")

    def install_cert(self):
        """Generates a self-signed TLS certificate using OpenSSL if none is present."""
        # Calculate the jail dir by getting the parent of the storage dir
        jail_dir = os.path.dirname(os.path.normpath(self.storage_dir))
        cert_dir = os.path.join(jail_dir, "certs")
        cert_path = os.path.join(cert_dir, "cert.pem")
        key_path = os.path.join(cert_dir, "key.pem")

        if os.path.exists(cert_path) and os.path.exists(key_path):
            print(f"✅ Certificates already exist in {cert_dir}. Skipping generation.")
            return

        print(f"Generating self-signed certificate in {cert_dir}...")
        os.makedirs(cert_dir, exist_ok=True)

        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes", "-subj", "/CN=Lume-Standalone-Server"
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"✅ Successfully generated cert.pem and key.pem in {cert_dir}")
            print("⚠️  Ensure the daemon has read access to these files if running under a different UID.")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to generate certificate:\n{e.stderr.decode('utf-8')}")
        except FileNotFoundError:
            print("❌ OpenSSL not found. Please install openssl or generate certificates manually.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lume Administrative Tool")
    parser.add_argument("command", choices=["check", "rebuild", "install-cert"], help="Action to perform")
    parser.add_argument("--dir", default="/var/lib/lume/data", help="Storage directory")

    args = parser.parse_args()
    admin = LumeAdmin(storage_dir=args.dir)

    if args.command == "check":
        admin.check_corruption()
    elif args.command == "rebuild":
        admin.rebuild_index()
    elif args.command == "install-cert":
        admin.install_cert()

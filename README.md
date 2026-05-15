# lume
Secure, failure-resistant email store with distributed compression and indexing.

## Architecture

Lume is designed as a secure, high-performance local MTA storage engine. It strictly separates the highly-compressible MIME text payload from incompressible binary attachments.

### Key Features
* **Zstandard Dictionary Compression:** Analyzes email corpus to build localized dictionaries, yielding massive compression ratios on standard email text.
* **Atomic Storage:** Emails are stored with `.tmp` staging and `fsync` guarantees to prevent corruption during unexpected termination.
* **OS-Level Sandboxing:** Operates in a highly constrained environment. Drops to a dedicated unprivileged user via `setresuid` and jails itself into its data directory via `chroot`.
* **Zero-Unsafe Rust:** Completely avoids `unsafe` blocks, relying strictly on the borrow checker for memory safety.
* **Cryptographic Integrity:** Payload verification utilizes xxhash64 for instant tamper and corruption detection.

## Building and Running

### Prerequisites
* Rust 1.70+
* Python 3.9+ (For the admin disaster-recovery tool)

### Setup
```bash
cargo build --release
```

To run the daemon locally (Requires root for `chroot` and privilege dropping):
```bash
sudo ./target/release/lume
```

### Testing
Run the comprehensive integration test suite using standard Cargo workflows:
```bash
cargo test
```

## Admin & Disaster Recovery Tools
Lume includes a Python-based utility to interact directly with the binary files without relying on the Rust daemon or SQLite index. This ensures data recovery is always possible.

Install Python dependencies locally:
```bash
python3 install_deps.py
```

Check the vault for corruption:
```bash
python3 lume_admin.py check --dir /var/lib/lume/data
```

Rebuild the SQLite index entirely from the file metadata:
```bash
python3 lume_admin.py rebuild --dir /var/lib/lume/data
```

## License
Licensed under the GNU Affero General Public License Version 3 (AGPL-3.0). See the `LICENSE` file for more details.

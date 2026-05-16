# Lume MTA & Samotop Integration: Developer Notes

## 1. Meta-Protocol: The Registry Extraction Protocol
During the development of the `lume_mta` binary, it became clear that trial-and-error API guessing (API thrashing) is a severe anti-pattern in strict Rust environments.

**Rule for Future Sessions:** When interacting with third-party crates (like `samotop`, `axum`, etc.) where the exact version's API or trait bounds are unknown, **DO NOT GUESS**. Instead, use a short Python diagnostic script to search the local `~/.cargo/registry/src/` cache and extract the exact trait definitions, enums, and struct fields. This guarantees 100% certainty and prevents compiler loops.

*(Note: This protocol has been formally appended to the `AGENTS.md` file for Jules and other agents.)*

## 2. Samotop v0.13.2 Architectural Specifics
The `samotop` v0.13.2 crate utilizes a highly specific, heavily lifetime-bound asynchronous architecture.

### A. Server Initialization
* **Struct:** The correct struct for binding the server is `samotop::server::TcpServer` (not `Server`).
* **Builder:** The `Builder::default()` uses the `.using(setup)` method to bind implementations, not `.with()`.

### B. The `Configuration` Wiring
To intercept emails, you must implement `MailSetup<Configuration>`.
`samotop` maintains internal vectors for its Guards and Dispatchers. To register custom logic, you must push boxed clones of your implementation into the `Configuration` struct directly.
```rust
impl MailSetup<Configuration> for LumeMta {
    fn setup(self, config: &mut Configuration) {
        config.guard.push(Box::new(self.clone()));
        config.dispatch.push(Box::new(self.clone()));
    }
}
```

### C. Traits and Pinned Futures
Implementing `MailGuard` (for connection/relay checks) and `MailDispatch` (for body parsing) requires exact lifetime matching.
* **Signatures:** They return `Pin<Box<dyn Future<Output = ...> + Send + Sync + 'f>>`
* **Lifetimes:** The implementations must explicitly declare `where 'a: 'f, 's: 'f` bounding the lifetime of `&self` and `&mut SmtpSession`.

### D. SMTP Rejection Enums
To fulfill the integration tests (554 Relay Denied and 550 Header checks), you must use the exact enums:
* **AddRecipientFailure:** Use `AddRecipientResult::Failed(AddRecipientFailure::RejectedPermanently, "554 5.7.1...".to_string())` to reject unauthorized domains.
* **StartMailFailure:** Used to reject the sender (`MAIL FROM`).
* **DispatchError:** Used during body processing.

## 3. The `MailDataSink` and Asynchronous Payloads
To capture the actual `DATA` stream of the email and write it to the `LumeEngine`, you must implement `MailDataSink`.

### Critical Discoveries:
1.  **It is an AsyncWrite Bound:** `MailDataSink` is a sealed trait. You do not implement it directly. Instead, you must implement `futures::io::AsyncWrite` on your sink struct. `samotop` provides a blanket implementation of `MailDataSink` for anything that implements `AsyncWrite + Send + Sync + 'static`.
2.  **Implementation:** You must implement `poll_write`, `poll_flush`, and `poll_close`.
3.  **Late Rejections:** To reject an email *after* the `DATA` block has started streaming (e.g., for missing `From:` or `To:` headers), you can return an `Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "550 ..."))` inside `poll_close()`.

## 4. Lume Engine Integration

### Atomic Storage Guarantees
The `LumeEngine::store_email` function is asynchronous. However, inside the Sink's `poll_close()` (where we finalize the transaction), we must ensure the data is fully `fsync`'d to disk and indexed in SQLite before the SMTP session returns a `250 OK` to the client.
* **Solution:** Use `tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(async { ... }))` to safely bridge the synchronous `poll_close` context with the asynchronous `LumeEngine` operations, guaranteeing atomicity.

### Struct Derivations (`Debug`)
`samotop` requires the MTA struct to implement `std::fmt::Debug`.
* Because `LumeMta` contains `LumeEngine`, and `LumeEngine` contains `CompressionManager`, the entire chain must derive `Debug`.
* `CompressionManager` uses external `zstd` dictionaries that do not implement `Debug`.
* **Solution:** Manually implement `Debug` for `CompressionManager` using `f.debug_struct("CompressionManager").finish_non_exhaustive()`, which unblocks `#[derive(Debug)]` for the rest of the application.

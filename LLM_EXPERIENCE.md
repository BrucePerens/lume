# LLM Experience & Architectural Context: LumeMta

## Overview
LumeMta is a custom Rust MTA built using the `samotop` library (v0.13.x) for the SMTP protocol layer and a custom `LumeEngine` for atomic, deduplicated SQLite storage.

## Core Architectural Challenge: The Runtime Schism
`samotop` handles high-concurrency networking using the `async-std` runtime. `LumeEngine` requires the `tokio` runtime for database and filesystem operations. Attempting to execute `tokio` futures directly inside `samotop`'s dispatch pipeline results in a panic (`there is no reactor running`).

Blocking the `async-std` thread using `std::thread::spawn` inside the sink is an anti-pattern that starves the network thread pool.

## The Solution: Return Receipt Architecture
To safely bridge the runtimes, we implemented a decoupled state machine inside the SMTP data sink.

### Components
1. **Cross-Runtime MPSC Channel:** An unbounded `tokio::sync::mpsc` channel routes payloads from the network thread to the database thread.
2. **The Envelope (`MailTask`):** The struct sent across the channel contains the payload, metadata, and crucially, a `tokio::sync::oneshot::Sender<std::io::Result<()>>`.
3. **Dedicated Tokio Worker:** A spawned Tokio task sits in a loop receiving envelopes. It executes the heavy SQLite operations (with a strict `tokio::time::timeout` to prevent deadlocks) and sends the result back via the `oneshot` sender.
4. **The State Machine Sink (`LumeSink`):** Implements `futures::io::AsyncWrite`. In `poll_close`, it creates the `oneshot` channel, sends the envelope to the Tokio worker, and transitions to a `WaitingForReceipt` state. It then safely polls the `oneshot::Receiver`, yielding `Poll::Pending` to `async-std` without blocking any OS threads, waking only when the DB operation completes.

## Samotop Quirks & Lessons Learned
When modifying or debugging the `samotop` integration, future LLMs must adhere to the following rules:

### 1. Explicit Routing over Blanket Traits
If a struct implements *both* `MailDispatch` and `MailGuard`, you **must** explicitly implement `MailSetup` for it.
* **Failure Mode:** Relying on `.using(mta)` without explicit setup causes Samotop to use its generic blanket implementation, which usually only wires up the `Dispatch` pipeline, leaving the `Guard` completely detached and silently ignoring security rules.
* **Fix:** `config.add_last_guard(instance_a); config.add_last_dispatch(instance_b);`

### 2. RFC-Compliant Error Masking
Samotop strictly adheres to SMTP RFCs and will override custom error strings depending on where the error originates.
* **Guard Layer:** Custom strings mapped to `RejectedPermanently` are converted to standard `550 Requested action not taken`.
* **Sink/Data Layer:** Sinks implementing `AsyncWrite` return `std::io::Error`. Samotop safely assumes *any* `io::Error` during data transfer is a temporary disk/storage failure and maps it to `450 Requested mail action not taken`. Do not expect custom strings to propagate back to the client during the `DATA` phase.

### 3. Dynamic Success Responses
When the data sink successfully closes (returning `Ok(())`), Samotop automatically generates a dynamic transaction ID. Test suites cannot use strict string matching for custom success strings; they must assert based on the standard `250 Queued as <id>` pattern (e.g., `response.contains("250") && response.to_lowercase().contains("queued")`).

## Required Traits
* Sinks must implement `futures::io::AsyncWrite` (not `tokio::io::AsyncWrite`).
* All structs passed into the `Builder` pipeline (`MailSetup`, `MailGuard`, `MailDispatch`) must implement `std::fmt::Debug`.

use axum_server::tls_rustls::RustlsConfig;
use std::env;
use std::path::PathBuf;

use lume::{api::build_router, security::secure_process, LumeEngine};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let dev_mode = args.contains(&"--dev-mode".to_string());

    let (jail_dir, internal_data_dir) = if dev_mode {
        println!("⚠️  DEV MODE ENABLED: Bypassing OS Sandbox and TLS.");
        let tmp = std::env::temp_dir().join(format!("lume_dev_{}", uuid::Uuid::new_v4()));
        (tmp.clone(), tmp.join("data"))
    } else {
        (PathBuf::from("/var/lib/lume"), PathBuf::from("/data"))
    };

    // 1. Initialize Engine BEFORE chrooting
    let engine = LumeEngine::new(jail_dir.join("data")).expect("Failed to initialize Engine");
    LumeEngine::init_db(&engine.db).expect("Failed to init SQLite");

    // Optional: Pre-register a test user if none exists
    let _ = engine.register_user("admin", "super_secret_password");
    if dev_mode {
        let _ = engine.register_user("api_test_user", "secure_password");
    }

    let state_engine = if dev_mode {
        // In dev mode, we do not chroot, so paths remain the same
        engine
    } else {
        // 2. Fix Ownership before jailing
        let target_uid = 1000;
        let target_gid = 1000;
        println!(
            "🔒 Setting directory ownership for chroot (UID: {target_uid}, GID: {target_gid})..."
        );
        lume::security::chown_recursive(&jail_dir, target_uid, target_gid)
            .expect("FATAL: Failed to change ownership of jail directory");

        // 3. CHROOT & DROP PRIVILEGES
        println!("🔒 Engaging OS Sandbox: chroot to /var/lib/lume, dropping privileges");
        secure_process(&jail_dir, target_uid, target_gid)
            .expect("FATAL: Failed to secure process!");

        // Update the engine's pathing to reflect its new reality inside the chroot
        let mut se = LumeEngine::new(internal_data_dir).expect("Failed internal remap");
        se.db = engine.db; // Move the connection over
        se
    };

    // 4. Define App with strict Security Headers
    let app = build_router(state_engine);

    // 5. Initialize TLS and start the server (or fallback to HTTP for dev mode)
    if dev_mode {
        // Parse port from args or use ephemeral
        let port_idx = args.iter().position(|a| a == "--port").map(|i| i + 1);
        let port: u16 = port_idx
            .and_then(|i| args.get(i))
            .and_then(|p| p.parse().ok())
            .unwrap_or(0); // 0 means OS will assign an ephemeral port

        let addr = format!("127.0.0.1:{}", port).parse().unwrap();
        let server = axum::Server::bind(&addr).serve(app.into_make_service());
        println!(
            "🚀 DEV Lume Server spinning up at http://{}",
            server.local_addr()
        );
        server.await.unwrap();
    } else {
        let addr = "0.0.0.0:8443".parse().unwrap();
        println!("🚀 Secure Lume Server spinning up at https://{}", addr);

        let cert_path = PathBuf::from("/certs/cert.pem");
        let key_path = PathBuf::from("/certs/key.pem");

        let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("FATAL: TLS certificates missing. cert.pem and key.pem MUST be present in /certs inside the jail.");

        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }
}

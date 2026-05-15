use axum::{
    extract::{Path, State},
    headers::{authorization::Basic, Authorization},
    http::{header, StatusCode},
    routing::{get, post},
    Json, Router, TypedHeader,
};
use axum_server::tls_rustls::RustlsConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::set_header::SetResponseHeaderLayer;

use lume::{security::secure_process, LumeEngine, LumeError};

struct AppState {
    engine: LumeEngine,
}

#[derive(Deserialize)]
struct StoreRequest {
    message_id: String,
    subject: String,
    sender: String,
    raw_content: Vec<u8>,
}

#[derive(Serialize)]
struct MailResponse {
    message_id: String,
    content: String,
}

#[tokio::main]
async fn main() {
    let jail_dir = PathBuf::from("/var/lib/lume");
    let internal_data_dir = PathBuf::from("/data");

    // 1. Initialize Engine BEFORE chrooting (in case it needs initial root permissions to create dirs)
    let engine = LumeEngine::new(jail_dir.join("data")).expect("Failed to initialize Engine");
    LumeEngine::init_db(&engine.db).expect("Failed to init SQLite");

    // Optional: Pre-register a test user if none exists (for demonstration)
    let _ = engine.register_user("admin", "super_secret_password");

    // 2. Fix Ownership before jailing
    let target_uid = 1000;
    let target_gid = 1000;
    println!("🔒 Setting directory ownership for chroot (UID: {target_uid}, GID: {target_gid})...");
    lume::security::chown_recursive(&jail_dir, target_uid, target_gid)
        .expect("FATAL: Failed to change ownership of jail directory");

    // 3. CHROOT & DROP PRIVILEGES
    println!("🔒 Engaging OS Sandbox: chroot to /var/lib/lume, dropping privileges");
    secure_process(&jail_dir, target_uid, target_gid).expect("FATAL: Failed to secure process!");

    // Update the engine's pathing to reflect its new reality inside the chroot
    let mut state_engine = LumeEngine::new(internal_data_dir).expect("Failed internal remap");
    state_engine.db = engine.db; // Move the connection over
    let state = Arc::new(AppState {
        engine: state_engine,
    });

    // 4. Define App with strict Security Headers
    let app = Router::new()
        .route("/mail", post(store_mail))
        .route("/mail/:message_id", get(retrieve_mail))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            header::HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .with_state(state);

    // 5. Initialize TLS and start the server
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

async fn store_mail(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Basic>>,
    Json(payload): Json<StoreRequest>,
) -> Result<StatusCode, StatusCode> {
    // Cryptographic Authentication
    let acl_id = state
        .engine
        .authenticate_user(auth.username(), auth.password())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let _path = state
        .engine
        .store_email(&payload.message_id, acl_id, &payload.raw_content)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let header = lume::storage::MailHeader {
        dict_id: state.engine.active_dict_version,
        acl_id,
        original_checksum: 0,
        text_len: 0,
    };

    state
        .engine
        .index_message(
            &payload.message_id,
            &header,
            &payload.subject,
            &payload.sender,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}

async fn retrieve_mail(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Basic>>,
    Path(message_id): Path<String>,
) -> Result<Json<MailResponse>, StatusCode> {
    // Cryptographic Authentication
    let acl_id = state
        .engine
        .authenticate_user(auth.username(), auth.password())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // ACL Check (Does this user own this email?)
    if state
        .engine
        .authorize_and_get_dict(&message_id, acl_id)
        .is_err()
    {
        return Err(StatusCode::FORBIDDEN);
    }

    match state.engine.get_email(&message_id).await {
        Ok(data) => {
            let content = String::from_utf8_lossy(&data).to_string();
            Ok(Json(MailResponse {
                message_id,
                content,
            }))
        }
        Err(LumeError::Corruption) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(LumeError::AccessDenied) => Err(StatusCode::FORBIDDEN),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

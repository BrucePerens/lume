use axum::{
    extract::{Path, State},
    headers::{authorization::Basic, Authorization},
    http::{header, StatusCode},
    routing::{get, post},
    Json, Router, TypedHeader,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::set_header::SetResponseHeaderLayer;

use lume::{LumeEngine, LumeError, security::secure_process};

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
    let internal_data_dir = PathBuf::from("/data"); // This will be /var/lib/lume/data inside the jail
    
    // 1. Initialize Engine BEFORE chrooting (in case it needs initial root permissions to create dirs)
    let engine = LumeEngine::new(jail_dir.join("data")).expect("Failed to initialize Engine");
    LumeEngine::init_db(&engine.db).expect("Failed to init SQLite");
    
    // Optional: Pre-register a test user if none exists (for demonstration)
    let _ = engine.register_user("admin", "super_secret_password");

    // 2. CHROOT & DROP PRIVILEGES
    // Assuming 'lume' user exists on the system with UID 1000 and GID 1000.
    // In production, you would fetch these dynamically via libc::getpwnam.
    println!("🔒 Engaging OS Sandbox: chroot to /var/lib/lume, dropping to uid 1000");
    secure_process(&jail_dir, 1000, 1000).expect("FATAL: Failed to secure process!");
    
    // Update the engine's pathing to reflect its new reality inside the chroot
    let mut state_engine = LumeEngine::new(internal_data_dir).expect("Failed internal remap");
    state_engine.db = engine.db; // Move the connection over
    let state = Arc::new(AppState { engine: state_engine });

    // 3. Define App with strict Security Headers
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

    let addr = "0.0.0.0:8080".parse().unwrap();
    println!("🚀 Secure Lume Server active at {}", addr);
    axum::Server::bind(&addr)
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
    let acl_id = state.engine.authenticate_user(auth.username(), auth.password())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let path = state.engine.store_email(&payload.message_id, acl_id, &payload.raw_content)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let header = lume::storage::MailHeader {
        dict_id: state.engine.active_dict_version,
        acl_id,
        original_checksum: 0, 
        text_len: 0,
    };

    state.engine.index_message(&payload.message_id, &header, &payload.subject, &payload.sender)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::CREATED)
}

async fn retrieve_mail(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Basic>>,
    Path(message_id): Path<String>,
) -> Result<Json<MailResponse>, StatusCode> {
    
    // Cryptographic Authentication
    let acl_id = state.engine.authenticate_user(auth.username(), auth.password())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // ACL Check (Does this user own this email?)
    if state.engine.authorize_and_get_dict(&message_id, acl_id).is_err() {
        return Err(StatusCode::FORBIDDEN);
    }
    
    match state.engine.get_email(&message_id).await {
        Ok(data) => {
            let content = String::from_utf8_lossy(&data).to_string();
            Ok(Json(MailResponse {
                message_id,
                content,
            }))
        },
        Err(LumeError::Corruption) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(LumeError::AccessDenied) => Err(StatusCode::FORBIDDEN),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

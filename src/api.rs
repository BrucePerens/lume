use axum::{
    extract::{Path, State},
    headers::{authorization::Basic, Authorization},
    http::{header, StatusCode},
    routing::{get, post},
    Json, Router, TypedHeader,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::{LumeEngine, LumeError};

pub struct AppState {
    pub engine: LumeEngine,
}

#[derive(Deserialize)]
pub struct StoreRequest {
    pub message_id: String,
    pub subject: String,
    pub sender: String,
    pub raw_content: Vec<u8>,
}

#[derive(Serialize)]
pub struct MailResponse {
    pub message_id: String,
    pub content: String,
}

/// Constructs the core Axum router, making it available for both the
/// main daemon runner and the test environment.
pub fn build_router(engine: LumeEngine) -> Router {
    let state = Arc::new(AppState { engine });

    Router::new()
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
        .with_state(state)
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

    let header = crate::storage::MailHeader {
        dict_id: state.engine.compression_manager.get_active_dict_id(),
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

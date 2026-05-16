use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
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

pub fn build_router(engine: LumeEngine) -> Router {
    let state = Arc::new(AppState { engine });

    Router::new()
        .route("/mail", post(store_mail))
        .route("/mail/{message_id}", get(retrieve_mail))
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

fn decode_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth_header = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if !auth_header.starts_with("Basic ") {
        return None;
    }
    let b64 = &auth_header[6..];

    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut decode_map = [255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        decode_map[c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for &b in b64.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = decode_map[b as usize];
        if val == 255 {
            continue;
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }

    let auth_str = String::from_utf8(out).ok()?;
    let mut parts = auth_str.splitn(2, ':');
    let username = parts.next()?.to_string();
    let password = parts.next()?.to_string();
    Some((username, password))
}

async fn store_mail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<StoreRequest>,
) -> Result<StatusCode, StatusCode> {
    let (username, password) = decode_basic_auth(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let acl_id = state
        .engine
        .authenticate_user(&username, &password)
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
    headers: HeaderMap,
    Path(message_id): Path<String>,
) -> Result<Json<MailResponse>, StatusCode> {
    let (username, password) = decode_basic_auth(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let acl_id = state
        .engine
        .authenticate_user(&username, &password)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

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

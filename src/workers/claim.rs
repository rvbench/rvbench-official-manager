//! Worker first-claim: machine endpoints (no credentials, rate-limited) plus the
//! human confirmation endpoints (login required). Owner always comes from the
//! approving session, never from the claim request (design §2).
use super::store::{self, ClaimRow, WorkerRecord};
use super::token as worker_token;
use crate::auth::{AuthError, AuthMode, Principal};
use crate::Manager;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use std::sync::Arc;

pub fn router() -> Router<Arc<Manager>> {
    Router::new()
        .route("/cluster/workers/claim", post(begin))
        .route("/cluster/workers/claim/{device_code}", get(poll))
        .route("/claims", get(list_claims))
        .route("/claims/{code}/approve", post(approve))
        .route("/claims/{code}/deny", post(deny))
}

/// 8-char code from the ambiguity-free alphabet (no 0/O/1/I).
fn new_code(rng: &mut impl rand::RngCore) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    let code: String = bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    format!("{}-{}", &code[..4], &code[4..])
}

pub(crate) async fn begin(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    if m.auth.config.mode == AuthMode::Off {
        return Err(AuthError::auth_disabled());
    }
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("-")
        .to_string();
    if !m.auth.claim_limiter.check(&ip, rvbench_protocol::seconds()) {
        return Err(AuthError::rate_limited());
    }
    let worker_id = body["worker_id"].as_str().unwrap_or_default().to_string();
    let board_id = body["board_id"].as_str().unwrap_or_default().to_string();
    let backend = body["backend"].as_str().unwrap_or_default().to_string();
    let kinds: Vec<String> = body["kinds"]
        .as_array()
        .map(|a| a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if worker_id.is_empty()
        || worker_id.len() > 64
        || !worker_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || board_id.is_empty()
        || board_id.len() > 64
        || !["k1", "k3"].contains(&backend.as_str())
        || kinds.is_empty()
        || kinds.iter().any(|k| !["func", "correctness", "performance"].contains(&k.as_str()))
    {
        return Err(AuthError::bad("invalid claim request"));
    }
    let now = rvbench_protocol::seconds();
    let wid_for_check = worker_id.clone();
    let (taken, pending_count) = m
        .auth
        .db
        .call(move |c| {
            let taken = store::worker_id_taken(c, &wid_for_check).map_err(AuthError::internal)?;
            let pending = store::list_pending_claims(c, now)
                .map_err(AuthError::internal)?
                .len();
            Ok((taken, pending))
        })
        .await?;
    if taken {
        return Err(AuthError::new(StatusCode::CONFLICT, "conflict", "worker_id already in use"));
    }
    if pending_count >= 20 {
        return Err(AuthError::rate_limited());
    }
    let (code, device_code) = {
        // ThreadRng is !Send; keep it inside this block so the handler future stays Send.
        let mut entropy = rand::rng();
        let code = new_code(&mut entropy);
        let mut device_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut entropy, &mut device_bytes);
        (
            code,
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                device_bytes,
            ),
        )
    };
    let verification = m
        .auth
        .config
        .base_url()
        .and_then(|b| b.join("/claim").ok())
        .map(|u| u.to_string())
        .unwrap_or_else(|| "/claim".into());
    let row = ClaimRow {
        code,
        device_code: device_code.clone(),
        worker_id,
        board_id,
        backend,
        kinds,
        environment: body["environment"].as_object().map(|o| Value::Object(o.clone())),
        source_ip: Some(ip),
        created_at: now,
        expires_at: now + 600.0,
        status: "pending".into(),
        approved_token: None,
        delivered_at: None,
    };
    m.auth
        .db
        .call({
            let r = row.clone();
            move |c| store::insert_claim(c, &r).map_err(AuthError::internal)
        })
        .await?;
    Ok(Json(json!({
        "code": row.code,
        "device_code": device_code,
        "verification_url": verification,
        "expires_in": 600,
        "interval": 5,
    })))
}

pub(crate) async fn poll(
    State(m): State<Arc<Manager>>,
    Path(device_code): Path<String>,
) -> Result<Response, AuthError> {
    if m.auth.config.mode == AuthMode::Off {
        return Err(AuthError::auth_disabled());
    }
    let now = rvbench_protocol::seconds();
    let row = m
        .auth
        .db
        .call(move |c| store::get_claim_by_device(c, &device_code).map_err(AuthError::internal))
        .await?;
    let Some(row) = row else {
        return Err(AuthError::missing());
    };
    match row.status.as_str() {
        "pending" if row.expires_at > now => Ok((
            StatusCode::ACCEPTED,
            Json(json!({"status": "pending"})),
        )
            .into_response()),
        "pending" => Ok((
            StatusCode::GONE,
            Json(json!({"status": "expired"})),
        )
            .into_response()),
        "denied" => Ok((StatusCode::GONE, Json(json!({"status": "denied"}))).into_response()),
        "approved" => {
            // The token leaves exactly once; later polls are 410.
            let token = m
                .auth
                .db
                .call({
                    let code = row.code.clone();
                    move |c| store::take_claim_token(c, &code, now).map_err(AuthError::internal)
                })
                .await?;
            match token {
                Some(t) => Ok(Json(json!({
                    "status": "approved",
                    "token": t,
                    "worker_id": row.worker_id,
                }))
                .into_response()),
                None => Ok((
                    StatusCode::GONE,
                    Json(json!({"status": "denied"})),
                )
                    .into_response()),
            }
        }
        _ => Ok((StatusCode::GONE, Json(json!({"status": "expired"}))).into_response()),
    }
}

pub(crate) async fn list_claims(
    State(m): State<Arc<Manager>>,
    _principal: axum::Extension<Principal>,
) -> Result<Json<Value>, AuthError> {
    let now = rvbench_protocol::seconds();
    // Refresh statuses so the page never shows expired rows as confirmable.
    m.auth
        .db
        .call(move |c| store::expire_claims(c, now).map_err(AuthError::internal))
        .await?;
    let rows = m
        .auth
        .db
        .call(move |c| store::list_pending_claims(c, now).map_err(AuthError::internal))
        .await?;
    Ok(Json(json!({"items": rows.iter().map(|r| r.to_view()).collect::<Vec<_>>()})))
}

pub(crate) async fn approve(
    State(m): State<Arc<Manager>>,
    Path(code): Path<String>,
    principal: axum::Extension<Principal>,
    body: Option<Json<Value>>,
) -> Result<Json<Value>, AuthError> {
    let visibility = body
        .as_ref()
        .and_then(|Json(b)| b["visibility"].as_str())
        .unwrap_or("private");
    if !["private", "public"].contains(&visibility) {
        return Err(AuthError::bad("visibility must be private or public"));
    }
    if visibility == "public" && !principal.is_admin {
        return Err(AuthError::forbidden("public workers require admin")
            .with_details(json!({"required": "worker:create:public"})));
    }
    let now = rvbench_protocol::seconds();
    let row = m
        .auth
        .db
        .call({
            let code = code.clone();
            move |c| store::get_claim_by_code(c, &code).map_err(AuthError::internal)
        })
        .await?;
    let Some(row) = row.filter(|r| r.status == "pending" && r.expires_at > now) else {
        return Err(AuthError::missing());
    };
    if m.auth.workers.get(&row.worker_id).is_some_and(|r| r.status != "revoked") {
        return Err(AuthError::new(StatusCode::CONFLICT, "conflict", "worker_id already in use"));
    }
    let plain = worker_token::generate();
    let record = WorkerRecord {
        worker_id: row.worker_id.clone(),
        owner_sub: if visibility == "public" {
            "org:rvbench".into()
        } else {
            principal.sub.clone()
        },
        owner_login: if visibility == "public" {
            "rvbench".into()
        } else {
            principal.login.clone()
        },
        visibility: visibility.into(),
        status: "pending".into(),
        token_sha256: worker_token::sha256_hex(&plain),
        token_prefix: worker_token::prefix(&plain),
        created_at: now,
        last_seen: None,
        revoked_at: None,
    };
    // Reserve the claim first (one-shot pending→approved); only the winner
    // inserts the worker record. Concurrent approvers see 409.
    let won = m
        .auth
        .db
        .call({
            let (code, owner, plain) = (code.clone(), record.owner_sub.clone(), plain.clone());
            move |c| {
                store::decide_claim(c, &code, "approved", Some(&owner), Some(&plain), now)
                    .map_err(AuthError::internal)
            }
        })
        .await?;
    if !won {
        return Err(AuthError::new(StatusCode::CONFLICT, "conflict", "claim already handled"));
    }
    m.auth
        .db
        .call({
            let record = record.clone();
            move |c| store::insert_worker(c, &record).map_err(AuthError::internal)
        })
        .await?;
    m.auth.workers.upsert(record.clone());
    crate::auth::audit::record(
        &m.auth,
        Some(&principal.sub),
        Some(&principal.login),
        "worker.claim.approve",
        Some(&record.worker_id),
        "ok",
        None,
    )
    .await;
    Ok(Json(record.to_json()))
}

pub(crate) async fn deny(
    State(m): State<Arc<Manager>>,
    Path(code): Path<String>,
    _principal: axum::Extension<Principal>,
) -> Result<Response, AuthError> {
    let now = rvbench_protocol::seconds();
    let won = m
        .auth
        .db
        .call(move |c| store::decide_claim(c, &code, "denied", None, None, now).map_err(AuthError::internal))
        .await?;
    if !won {
        return Err(AuthError::missing());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

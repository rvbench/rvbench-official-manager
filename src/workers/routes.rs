//! /workers management endpoints (plan W1). Guards: route-level "any logged-in
//! user" plus resource-level owner-or-admin checks; visibility=public creation
//! requires worker:create:public (admin only).
use super::store::{self, WorkerRecord};
use super::token as worker_token;
use crate::auth::{AuthError, Principal};
use crate::Manager;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use std::sync::Arc;

pub fn router() -> Router<Arc<Manager>> {
    Router::new()
        .route(
            "/workers",
            post(create).get(crate::workers::routes::list),
        )
        .route("/workers/{id}", get(get_one).delete(delete))
        .route("/workers/{id}/tokens", post(rotate))
}

pub(crate) async fn create(
    State(m): State<Arc<Manager>>,
    principal: axum::Extension<Principal>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    let worker_id = body["worker_id"].as_str().unwrap_or_default().to_string();
    let valid = !worker_id.is_empty()
        && worker_id.len() <= 64
        && worker_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid {
        return Err(AuthError::bad("worker_id must be [A-Za-z0-9_-]{1,64}"));
    }
    let visibility = match body["visibility"].as_str() {
        None | Some("private") => "private",
        Some("public") => {
            if !principal.is_admin {
                return Err(AuthError::forbidden("public workers require admin")
                    .with_details(json!({"required": "worker:create:public"})));
            }
            "public"
        }
        Some(_) => return Err(AuthError::bad("visibility must be private or public")),
    };
    let (owner_sub, owner_login) = if visibility == "public" {
        ("org:rvbench".to_string(), "rvbench".to_string())
    } else {
        (principal.sub.clone(), principal.login.clone())
    };
    let now = rvbench_protocol::seconds();
    let plain = worker_token::generate();
    let sha = worker_token::sha256_hex(&plain);
    let prefix = worker_token::prefix(&plain);
    let record = WorkerRecord {
        worker_id: worker_id.clone(),
        owner_sub,
        owner_login,
        visibility: visibility.into(),
        status: "pending".into(),
        token_sha256: sha,
        token_prefix: prefix,
        created_at: now,
        last_seen: None,
        revoked_at: None,
    };
    let inserted = m
        .auth
        .db
        .call({
            let r = record.clone();
            move |c| {
                if store::worker_id_taken(c, &r.worker_id).map_err(AuthError::internal)? {
                    return Ok(false);
                }
                store::insert_worker(c, &r).map_err(AuthError::internal)?;
                Ok(true)
            }
        })
        .await?;
    if !inserted {
        return Err(AuthError::new(StatusCode::CONFLICT, "conflict", "worker_id already in use"));
    }
    m.auth.workers.upsert(record.clone());
    Ok(Json(json!({
        "worker": record.to_json(),
        "token": {"token": plain, "token_prefix": record.token_prefix, "created_at": crate::auth::iso(now)},
    })))
}

pub(crate) async fn list(State(m): State<Arc<Manager>>, principal: axum::Extension<Principal>) -> Json<Value> {
    let visible: Vec<_> = m
        .auth
        .workers
        .all()
        .into_iter()
        .filter(|r| {
            principal.is_admin || r.is_public() || r.owner_sub == principal.sub
        })
        .collect();
    Json(json!({"items": visible.iter().map(|r| r.to_json()).collect::<Vec<_>>()}))
}

pub(crate) async fn get_one(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, AuthError> {
    let Some(record) = m.auth.workers.get(&id) else {
        return Err(AuthError::missing());
    };
    // Public route (public records are world-readable), so resolve inline instead
    // of relying on a guard-inserted extension.
    let principal = m.auth.resolve(&headers).await;
    let allowed = record.is_public()
        || principal
            .as_ref()
            .is_some_and(|p| p.is_admin || p.sub == record.owner_sub);
    if !allowed {
        // Foreign private workers are indistinguishable from missing ones.
        return Err(AuthError::missing());
    }
    Ok(Json(record.to_json()))
}

/// Owner or admin; revoking a worker with live assignments returns 409 (drain first).
pub(crate) async fn delete(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    principal: axum::Extension<Principal>,
) -> Result<Response, AuthError> {
    let Some(record) = m.auth.workers.get(&id) else {
        return Err(AuthError::missing());
    };
    if !principal.is_admin && record.owner_sub != principal.sub {
        return Err(AuthError::missing());
    }
    let busy = m
        .store
        .tx({
            let id = id.clone();
            move |s| {
                Ok(s.assignments.values().any(|g| {
                    g.assignment.worker_id == id
                        && !rvbench_protocol::terminal(&s.jobs[&g.assignment.job_id].state)
                }))
            }
        })
        .await
        .map_err(|e| AuthError::internal(e.1))?;
    if busy {
        return Err(AuthError::new(
            StatusCode::CONFLICT,
            "conflict",
            "worker has in-flight assignments; drain first",
        ));
    }
    let now = rvbench_protocol::seconds();
    let wid_revoke = id.clone();
    m.auth
        .db
        .call(move |c| {
            store::revoke_worker(c, &wid_revoke, now).map_err(AuthError::internal)
        })
        .await?;
    if let Some(r) = m.auth.workers.get(&id) {
        let mut revoked = r.clone();
        revoked.status = "revoked".into();
        revoked.revoked_at = Some(now);
        m.auth.workers.upsert(revoked);
    }
    crate::auth::audit::record(
        &m.auth,
        Some(&principal.sub),
        Some(&principal.login),
        "worker.revoke",
        Some(&id),
        "ok",
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Rotate: the plaintext token appears once; the old one dies immediately.
pub(crate) async fn rotate(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    principal: axum::Extension<Principal>,
) -> Result<Json<Value>, AuthError> {
    let Some(record) = m.auth.workers.get(&id) else {
        return Err(AuthError::missing());
    };
    if !principal.is_admin && record.owner_sub != principal.sub {
        return Err(AuthError::missing());
    }
    if record.status == "revoked" {
        return Err(AuthError::missing());
    }
    let now = rvbench_protocol::seconds();
    let plain = worker_token::generate();
    let sha = worker_token::sha256_hex(&plain);
    let prefix = worker_token::prefix(&plain);
    let wid = id.clone();
    let sha_for_db = sha.clone();
    let prefix_for_db = prefix.clone();
    let rotated = m
        .auth
        .db
        .call(move |c| {
            store::rotate_token(c, &wid, &sha_for_db, &prefix_for_db, now)
                .map_err(AuthError::internal)
        })
        .await?;
    if !rotated {
        return Err(AuthError::missing());
    }
    let mut updated = record;
    updated.token_sha256 = sha;
    updated.token_prefix = prefix.clone();
    updated.created_at = now;
    updated.status = if updated.last_seen.is_some() { "active".into() } else { "pending".into() };
    m.auth.workers.upsert(updated.clone());
    Ok(Json(json!({
        "worker": updated.to_json(),
        "token": {"token": plain, "token_prefix": prefix, "created_at": crate::auth::iso(now)},
    })))
}

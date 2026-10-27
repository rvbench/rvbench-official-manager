//! /auth/* endpoints (13, contract/openapi.yaml v1.4). Login endpoints are IP
//! rate-limited (10/min); cookie-authenticated writes verify Origin (design D10).
use super::provider::{Membership, Pkce, ProviderUser};
use super::store;
use super::{
    AuthMode, Principal, Role, audit, build_cookie, cookie_value, error::AuthError, iso,
    safe_redirect, session,
};
use crate::Manager;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

pub fn router() -> Router<Arc<Manager>> {
    Router::new()
        .route("/auth/config", get(config))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/github/exchange", post(exchange))
        .route("/auth/me", get(me).delete(me_delete))
        .route("/auth/logout", post(logout))
        .route("/auth/sessions", get(sessions))
        .route("/auth/sessions/{id}", delete(revoke_session))
        .route("/auth/tokens", post(token_create).get(tokens_list))
        .route("/auth/tokens/{id}", delete(token_revoke))
        .route("/auth/users", get(users_list))
        .route("/auth/users/{sub}/roles", patch(user_roles_patch))
        .route("/auth/audit", get(audit_list))
}

async fn config(State(m): State<Arc<Manager>>) -> Json<Value> {
    let a = &m.auth;
    let enabled = a.config.mode != AuthMode::Off;
    Json(json!({
        "enabled": enabled,
        "provider": enabled.then(|| a.provider.kind()),
        "display_name": enabled.then(|| a.provider.display_name()),
        "login_url": enabled.then_some("/auth/login"),
        "logout_url": enabled.then_some("/auth/logout"),
    }))
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
/// Origin must match public_base_url for cookie-authenticated writes; absent Origin
/// passes (SameSite=Lax already blocks cross-site posts from carrying the cookie).
fn origin_ok(headers: &HeaderMap, m: &Manager) -> bool {
    let Some(base) = m.auth.config.base_url() else {
        return true;
    };
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(|o| reqwest::Url::parse(o).ok())
    else {
        return true;
    };
    origin.host_str() == base.host_str()
        && origin.port_or_known_default() == base.port_or_known_default()
}
fn redirect_response(location: &str, cookies: Vec<String>) -> Response {
    let mut r = StatusCode::FOUND.into_response();
    r.headers_mut()
        .insert(header::LOCATION, location.parse().unwrap());
    for c in cookies {
        if let Ok(v) = c.parse() {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}
/// Shared login tail: persist principal, resolve team membership (degrade on
/// provider failure rather than fail the login), create the session, audit.
/// Returns (rvb token, expires_at, role names, first_login) — the token
/// plaintext appears once. first_login is read off the upserted row: a principal
/// whose first_seen equals last_seen was just created (plan M1).
async fn establish(
    m: &Manager,
    user: &ProviderUser,
    provider_token: Option<&str>,
    kind: &str,
    ttl: f64,
    ua: Option<&str>,
    ip: Option<&str>,
) -> Result<(String, f64, Vec<&'static str>, bool), AuthError> {
    let membership = m
        .auth
        .provider
        .team_membership(provider_token.map(str::to_string), user.login.clone())
        .await;
    let early = matches!(membership, Ok(Membership::Active));
    let degraded = membership.is_err();
    let mut roles = vec!["user"];
    if early {
        roles.push("early_access");
    }
    if m.auth.admins.iter().any(|a| *a == user.sub) {
        roles.push("admin");
    }
    let token = session::generate();
    let sha = session::sha256_hex(&token);
    let now = rvbench_protocol::seconds();
    let cache_ttl = if degraded {
        60.0
    } else {
        m.auth.config.role_cache_ttl()
    };
    let provider_kind = m.auth.provider.kind();
    let (sub, ip_owned, kind_owned, ua_owned) = (
        user.sub.clone(),
        ip.map(str::to_string),
        kind.to_string(),
        ua.map(str::to_string),
    );
    let (expires, first_login) = m
        .auth
        .db
        .call({
            let user = user.clone();
            let sha = sha.clone();
            let provider_token = provider_token.map(str::to_string);
            move |c| {
                let row = store::upsert_principal(c, &user, provider_kind, now)?;
                store::cache_put(c, &sub, early, degraded, now, cache_ttl)?;
                let expires = store::insert_session(
                    c,
                    &sha,
                    &sub,
                    &kind_owned,
                    ttl,
                    ua_owned.as_deref(),
                    ip_owned.as_deref(),
                    provider_token.as_deref(),
                    now,
                )?;
                Ok((expires, row.first_seen == row.last_seen))
            }
        })
        .await?;
    audit::record(
        &m.auth,
        Some(&user.sub),
        Some(&user.login),
        "login",
        None,
        "ok",
        ip,
    )
    .await;
    Ok((token, expires, roles, first_login))
}

async fn login(
    State(m): State<Arc<Manager>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    if m.auth.config.mode == AuthMode::Off {
        return Err(AuthError::auth_disabled());
    }
    let ip = client_ip(&headers);
    if !m
        .auth
        .limiter
        .check(ip.as_deref().unwrap_or("-"), rvbench_protocol::seconds())
    {
        return Err(AuthError::rate_limited());
    }
    let redirect = safe_redirect(q.get("redirect").map(String::as_str))?;
    let secure = m.auth.config.cookie_secure();
    if m.auth.provider.kind() == "static" {
        // Dev/test shortcut: the static provider has no authorize step, so the
        // browser "logs in" by naming a configured user (design §8.4).
        let name = q.get("login").cloned().unwrap_or_default();
        let user = m
            .auth
            .provider
            .userinfo(name)
            .await
            .map_err(|e| AuthError::bad(format!("static login: {}", e.message)))?;
        let (token, _, _, first_login) = establish(
            &m,
            &user,
            Some(&user.login),
            "web",
            m.auth.config.session_ttl(),
            None,
            ip.as_deref(),
        )
        .await?;
        // First login lands on the welcome screen, overriding the redirect param (M1).
        let landing = if first_login {
            "/ui#/welcome".to_string()
        } else {
            redirect
        };
        return Ok(redirect_response(
            &landing,
            vec![build_cookie("rvb_session", &token, None, secure)],
        ));
    }
    let state = session::generate();
    let pkce = Pkce::new();
    let now = rvbench_protocol::seconds();
    let (state_key, verifier, redirect_after) = (state.clone(), pkce.verifier.clone(), redirect);
    m.auth
        .db
        .call(move |c| store::state_insert(c, &state_key, &verifier, &redirect_after, now, 600.0))
        .await?;
    let uri = m
        .auth
        .config
        .base_url()
        .and_then(|b| b.join("/auth/callback").ok())
        .map(|u| u.to_string())
        .ok_or_else(|| AuthError::internal("public_base_url required for github login"))?;
    let location = m.auth.provider.authorize_url(&state, &pkce, &uri);
    Ok(redirect_response(
        &location,
        vec![build_cookie("rvb_oauth_state", &state, Some(600), secure)],
    ))
}

async fn callback(
    State(m): State<Arc<Manager>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    if m.auth.config.mode == AuthMode::Off {
        return Err(AuthError::auth_disabled());
    }
    let query_state = q.get("state").cloned().unwrap_or_default();
    let cookie_state = cookie_value(&headers, "rvb_oauth_state").unwrap_or_default();
    if query_state.is_empty() || query_state != cookie_state {
        return Err(AuthError::state_invalid("state cookie mismatch"));
    }
    let now = rvbench_protocol::seconds();
    let state_key = query_state;
    let Some((verifier, redirect)) = m
        .auth
        .db
        .call(move |c| store::state_consume(c, &state_key, now))
        .await?
    else {
        return Err(AuthError::state_invalid("state expired or already used"));
    };
    let code = q.get("code").cloned().unwrap_or_default();
    let uri = m
        .auth
        .config
        .base_url()
        .and_then(|b| b.join("/auth/callback").ok())
        .map(|u| u.to_string())
        .ok_or_else(|| AuthError::internal("public_base_url required for github login"))?;
    let redirect = safe_redirect(Some(&redirect))?;
    let flow = async {
        let token = m
            .auth
            .provider
            .exchange_code(code, Pkce { verifier }, uri)
            .await?;
        let user = m.auth.provider.userinfo(token.clone()).await?;
        Ok::<_, AuthError>((token, user))
    };
    match flow.await {
        Ok((token, user)) => {
            let (rvb_token, _, _, first_login) = establish(
                &m,
                &user,
                Some(&token),
                "web",
                m.auth.config.session_ttl(),
                None,
                None,
            )
            .await?;
            let secure = m.auth.config.cookie_secure();
            // First login lands on the welcome screen, overriding the redirect param (M1).
            let landing = if first_login {
                "/ui#/welcome".to_string()
            } else {
                redirect
            };
            Ok(redirect_response(
                &landing,
                vec![
                    build_cookie("rvb_session", &rvb_token, None, secure),
                    build_cookie("rvb_oauth_state", "", Some(0), secure),
                ],
            ))
        }
        Err(_) => {
            // Provider trouble at callback time: send the browser home with a code
            // instead of a bare JSON error page (design §5.1).
            audit::record(&m.auth, None, None, "login_failed", None, "error", None).await;
            Ok(redirect_response(
                "/ui?auth_error=provider_unavailable",
                Vec::new(),
            ))
        }
    }
}

async fn exchange(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    if m.auth.config.mode == AuthMode::Off {
        return Err(AuthError::auth_disabled());
    }
    let ip = client_ip(&headers);
    if !m
        .auth
        .limiter
        .check(ip.as_deref().unwrap_or("-"), rvbench_protocol::seconds())
    {
        return Err(AuthError::rate_limited());
    }
    let access_token = body["access_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if access_token.is_empty() || access_token.len() > 512 {
        return Err(AuthError::bad("access_token required (max 512 chars)"));
    }
    match m.auth.provider.userinfo(access_token.clone()).await {
        Ok(user) => {
            let (token, expires, roles, _) = establish(
                &m,
                &user,
                Some(&access_token),
                "cli",
                m.auth.config.cli_ttl(),
                None,
                ip.as_deref(),
            )
            .await?;
            Ok(Json(json!({
                "token": token,
                "token_type": "Bearer",
                "expires_at": iso(expires),
                "principal": {"sub": user.sub, "login": user.login, "roles": roles},
            })))
        }
        Err(e) => {
            audit::record(
                &m.auth,
                None,
                None,
                "login_failed",
                None,
                "denied",
                ip.as_deref(),
            )
            .await;
            Err(AuthError::grant_invalid(e.message))
        }
    }
}

fn me_json(p: &Principal) -> Value {
    // avatar_url passes through unchanged; the &s=96 sizing convention is a
    // frontend concern (plan §2), so the URL is never rewritten here.
    json!({
        "principal": {
            "sub": p.sub, "login": p.login, "name": p.name, "email": p.email, "avatar_url": p.avatar_url,
            "provider": p.provider, "created_at": iso(p.first_seen),
            "roles": p.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
        },
        "permissions": p.permissions.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
        "roles_stale": p.roles_stale,
        "session": {"kind": p.session_kind, "expires_at": iso(p.session_expires_at)},
        "is_first_login": p.first_seen > 0.0 && p.first_seen == p.last_seen,
    })
}
async fn me(State(m): State<Arc<Manager>>, headers: HeaderMap) -> Result<Json<Value>, AuthError> {
    match m.auth.resolve(&headers).await {
        Some(p) => Ok(Json(me_json(&p))),
        None => Err(AuthError::unauthenticated("not logged in")),
    }
}

async fn logout(State(m): State<Arc<Manager>>, headers: HeaderMap) -> Result<Response, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    if super::bearer_token(&headers).is_none() && !origin_ok(&headers, &m) {
        return Err(AuthError::forbidden("origin mismatch"));
    }
    let sha = p.session_sha256.clone();
    let now = rvbench_protocol::seconds();
    m.auth
        .db
        .call(move |c| store::revoke_by_sha(c, &sha, now))
        .await?;
    audit::record(
        &m.auth,
        Some(&p.sub),
        Some(&p.login),
        "logout",
        None,
        "ok",
        None,
    )
    .await;
    let clear = build_cookie("rvb_session", "", Some(0), m.auth.config.cookie_secure());
    let mut r = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = clear.parse() {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    Ok(r)
}

async fn sessions(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    let sub = p.sub.clone();
    let items = m
        .auth
        .db
        .call(move |c| store::list_sessions(c, &sub))
        .await?;
    Ok(Json(json!({"items": items.iter().map(|s| json!({
        "id": s.id16(),
        "kind": s.kind,
        "label": s.label,
        "current": s.token_sha256 == p.session_sha256,
        "created_at": iso(s.created_at),
        "expires_at": iso(s.expires_at),
        "last_seen": iso(s.last_seen),
        "revoked": s.revoked_at.is_some(),
        "user_agent": s.user_agent,
        "ip": s.ip,
    })).collect::<Vec<_>>()})))
}

async fn revoke_session(
    State(m): State<Arc<Manager>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    if super::bearer_token(&headers).is_none() && !origin_ok(&headers, &m) {
        return Err(AuthError::forbidden("origin mismatch"));
    }
    // Non-owners get 404, mirroring job visibility: someone else's session id
    // must not be confirmable (design §2 resource ownership).
    let id_for_lookup = id.clone();
    let row = m
        .auth
        .db
        .call(move |c| store::session_by_id(c, &id_for_lookup))
        .await?;
    let Some(row) = row.filter(|r| r.sub == p.sub || p.is_admin) else {
        return Err(AuthError::missing());
    };
    let now = rvbench_protocol::seconds();
    let sha = row.token_sha256.clone();
    m.auth
        .db
        .call(move |c| store::revoke_by_sha(c, &sha, now))
        .await?;
    audit::record(
        &m.auth,
        Some(&row.sub),
        None,
        "session.revoke",
        Some(&id),
        "ok",
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// POST /auth/tokens (M2): mint a long-lived token from a web session. Bearer
/// callers are refused outright so a leaked token cannot beget more tokens.
async fn token_create(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    if super::bearer_token(&headers).is_some() {
        return Err(AuthError::forbidden(
            "token creation requires a web session",
        ));
    }
    if !origin_ok(&headers, &m) {
        return Err(AuthError::forbidden("origin mismatch"));
    }
    let label = body["label"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(64).collect::<String>());
    let ttl_days = body["ttl_days"].as_u64().unwrap_or(30).clamp(1, 365);
    let token = session::generate();
    let sha = session::sha256_hex(&token);
    let id: String = sha.chars().take(16).collect();
    let now = rvbench_protocol::seconds();
    let sub = p.sub.clone();
    let expires = m
        .auth
        .db
        .call({
            let sha = sha.clone();
            let label = label.clone();
            move |c| {
                let expires = store::insert_session(
                    c,
                    &sha,
                    &sub,
                    "token",
                    ttl_days as f64 * 86400.0,
                    None,
                    None,
                    None,
                    now,
                )?;
                store::set_session_label(c, &sha, label.as_deref())?;
                Ok(expires)
            }
        })
        .await?;
    // audit::record has no detail channel; write directly so the label survives.
    let (audit_sub, audit_id, detail) = (
        p.sub.clone(),
        id.clone(),
        json!({"label": label}).to_string(),
    );
    let _ = m
        .auth
        .db
        .call(move |c| {
            store::audit_append(
                c,
                rvbench_protocol::seconds(),
                Some(&audit_sub),
                None,
                "token.create",
                Some(&audit_id),
                "ok",
                None,
                Some(&detail),
            )
        })
        .await;
    Ok(Json(json!({
        "token": token,
        "token_type": "Bearer",
        "expires_at": iso(expires),
        "id": id,
    })))
}

/// GET /auth/tokens (M2): machine-facing credentials only (cli/token kinds);
/// web sessions stay on /auth/sessions.
async fn tokens_list(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    let sub = p.sub.clone();
    let items = m
        .auth
        .db
        .call(move |c| store::list_sessions(c, &sub))
        .await?;
    Ok(Json(json!({"items": items.iter()
        .filter(|s| s.kind == "cli" || s.kind == "token")
        .map(|s| json!({
            "id": s.id16(),
            "kind": s.kind,
            "label": s.label,
            "created_at": iso(s.created_at),
            "expires_at": iso(s.expires_at),
            "last_used": iso(s.last_seen),
            "revoked": s.revoked_at.is_some(),
        })).collect::<Vec<_>>()})))
}

/// DELETE /auth/tokens/{id} (M2): owner or admin; foreign ids are not
/// confirmable (404), mirroring session revocation.
async fn token_revoke(
    State(m): State<Arc<Manager>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    if super::bearer_token(&headers).is_none() && !origin_ok(&headers, &m) {
        return Err(AuthError::forbidden("origin mismatch"));
    }
    let id_for_lookup = id.clone();
    let row = m
        .auth
        .db
        .call(move |c| store::session_by_id(c, &id_for_lookup))
        .await?;
    let Some(row) =
        row.filter(|r| (r.kind == "cli" || r.kind == "token") && (r.sub == p.sub || p.is_admin))
    else {
        return Err(AuthError::missing());
    };
    let now = rvbench_protocol::seconds();
    let sha = row.token_sha256.clone();
    m.auth
        .db
        .call(move |c| store::revoke_by_sha(c, &sha, now))
        .await?;
    audit::record(
        &m.auth,
        Some(&row.sub),
        None,
        "token.revoke",
        Some(&id),
        "ok",
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// DELETE /auth/me (M3): tombstone the account. History keeps the sub for task
/// attribution; the last admin is protected so the deployment stays manageable.
async fn me_delete(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    if super::bearer_token(&headers).is_none() && !origin_ok(&headers, &m) {
        return Err(AuthError::forbidden("origin mismatch"));
    }
    if body["confirm_login"].as_str() != Some(p.login.as_str()) {
        return Err(AuthError::bad("confirm_login must match the current login"));
    }
    let config_others = m.auth.admins.iter().filter(|a| **a != p.sub).count();
    let db_admins = m.auth.db.call(|c| store::admin_grant_subs(c)).await?;
    let db_others = db_admins.iter().filter(|s| **s != p.sub).count();
    if config_others == 0 && db_others == 0 {
        return Err(AuthError::conflict(
            "cannot delete the last admin; grant admin to someone else first",
        ));
    }
    let now = rvbench_protocol::seconds();
    let sub = p.sub.clone();
    let (live, gone) = m
        .auth
        .db
        .call(move |c| {
            // Count before the tombstone so the audit detail can carry it.
            let live = store::list_sessions(c, &sub)?
                .iter()
                .filter(|s| s.revoked_at.is_none())
                .count() as u64;
            let gone = store::tombstone_principal(c, &sub, now)?.is_some();
            Ok((live, gone))
        })
        .await?;
    if !gone {
        return Err(AuthError::missing());
    }
    // Detail carries counts only — never the wiped profile content (plan M3).
    let (audit_sub, detail) = (p.sub.clone(), json!({"sessions_revoked": live}).to_string());
    let _ = m
        .auth
        .db
        .call(move |c| {
            store::audit_append(
                c,
                rvbench_protocol::seconds(),
                Some(&audit_sub),
                None,
                "account.delete",
                None,
                "ok",
                None,
                Some(&detail),
            )
        })
        .await;
    let clear = build_cookie("rvb_session", "", Some(0), m.auth.config.cookie_secure());
    let mut r = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = clear.parse() {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    Ok(r)
}

/// Effective roles for the console views: config list plus live DB grants.
fn effective_roles(m: &Manager, sub: &str, db_roles: &[String]) -> Vec<&'static str> {
    let mut roles = vec!["user"];
    if m.auth.admins.iter().any(|a| a == sub) || db_roles.iter().any(|r| r == "admin") {
        roles.push("admin");
    }
    if db_roles.iter().any(|r| r == "early_access") {
        roles.push("early_access");
    }
    if db_roles.iter().any(|r| r == "viewer") {
        roles.push("viewer");
    }
    roles
}

/// GET /auth/users (M4): admin console listing.
async fn users_list(
    State(m): State<Arc<Manager>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    if !p.is_admin {
        return Err(AuthError::forbidden("admin only"));
    }
    let limit = q
        .get("limit")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let offset = q
        .get("cursor")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let (search, role) = (q.get("q").cloned(), q.get("role").cloned());
    let (rows, has_more) = m
        .auth
        .db
        .call(move |c| store::list_users(c, search.as_deref(), role.as_deref(), limit, offset))
        .await?;
    let items = rows
        .iter()
        .map(|u| {
            json!({
                "sub": u.sub, "login": u.login, "name": u.name,
                "email": u.email, "avatar_url": u.avatar_url,
                "roles": effective_roles(&m, &u.sub, &u.db_roles),
                "deleted": u.deleted_at.is_some(),
                "first_seen": iso(u.first_seen),
                "last_seen": iso(u.last_seen),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(
        json!({"items": items, "next": has_more.then(|| (offset + limit).to_string())}),
    ))
}

/// PATCH /auth/users/{sub}/roles (M4; viewer added by plan C1): grant/revoke
/// early_access, admin or viewer. The role cache drop shares the same db.call,
/// so a granted role is live on the target's very next request without a
/// re-login.
async fn user_roles_patch(
    State(m): State<Arc<Manager>>,
    axum::extract::Path(sub): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    if !p.is_admin {
        return Err(AuthError::forbidden("admin only"));
    }
    if super::bearer_token(&headers).is_none() && !origin_ok(&headers, &m) {
        return Err(AuthError::forbidden("origin mismatch"));
    }
    let pick = |key: &str| -> Vec<String> {
        body[key]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let (grant, revoke) = (pick("grant"), pick("revoke"));
    if grant
        .iter()
        .chain(revoke.iter())
        .any(|r| Role::from_grant(r).is_none())
    {
        return Err(AuthError::bad(
            "grantable roles are early_access, admin and viewer only",
        ));
    }
    let sub_check = sub.clone();
    let row = m
        .auth
        .db
        .call(move |c| store::get_principal(c, &sub_check))
        .await?;
    if row.is_none_or(|r| r.deleted_at.is_some()) {
        return Err(AuthError::missing());
    }
    // 409 only when the write would leave zero effective admins: nobody else
    // holds admin (config or DB) and this op strips it from the sub. A
    // config-listed sub keeps admin regardless, but the console must still
    // refuse to "remove" the sole admin rather than pretend it worked.
    let config_others = m.auth.admins.iter().filter(|a| **a != sub).count();
    let db_admins = m.auth.db.call(|c| store::admin_grant_subs(c)).await?;
    let db_others = db_admins.iter().filter(|s| **s != sub).count();
    if config_others == 0 && db_others == 0 && revoke.iter().any(|r| r == "admin") {
        return Err(AuthError::conflict("cannot revoke the last admin"));
    }
    let now = rvbench_protocol::seconds();
    let (target, granted_by) = (sub.clone(), p.sub.clone());
    let db_roles = m
        .auth
        .db
        .call({
            let grant = grant.clone();
            let revoke = revoke.clone();
            move |c| {
                if !grant.is_empty() {
                    let refs: Vec<&str> = grant.iter().map(String::as_str).collect();
                    store::grant_roles(c, &target, &refs, &granted_by, now)?;
                }
                if !revoke.is_empty() {
                    let refs: Vec<&str> = revoke.iter().map(String::as_str).collect();
                    store::revoke_roles(c, &target, &refs, now)?;
                }
                store::cache_delete(c, &target)?;
                store::grants_for(c, &target)
            }
        })
        .await?;
    audit::record(
        &m.auth,
        Some(&p.sub),
        None,
        "roles.update",
        Some(&sub),
        "ok",
        None,
    )
    .await;
    Ok(Json(json!({"roles": effective_roles(&m, &sub, &db_roles)})))
}

async fn audit_list(
    State(m): State<Arc<Manager>>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    let Some(p) = m.auth.resolve(&headers).await else {
        return Err(AuthError::unauthenticated("not logged in"));
    };
    if !p.is_admin {
        return Err(AuthError::forbidden("admin only"));
    }
    let since = q
        .get("since")
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.timestamp() as f64);
    let limit = q
        .get("limit")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let items = audit::query(
        &m.auth,
        q.get("sub").cloned(),
        q.get("action").cloned(),
        since,
        limit,
    )
    .await?;
    Ok(Json(json!({"items": items})))
}

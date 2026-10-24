//! Append-only audit trail; never records tokens or request bodies (design D11).
use super::store;
use super::AuthState;
use serde_json::Value;

pub async fn record(
    state: &AuthState,
    sub: Option<&str>,
    login: Option<&str>,
    action: &str,
    target: Option<&str>,
    result: &str,
    ip: Option<&str>,
) {
    let (sub, login, action, target, result, ip) = (
        sub.map(str::to_string),
        login.map(str::to_string),
        action.to_string(),
        target.map(str::to_string),
        result.to_string(),
        ip.map(str::to_string),
    );
    let _ = state
        .db
        .call(move |c| {
            store::audit_append(
                c,
                rvbench_protocol::seconds(),
                sub.as_deref(),
                login.as_deref(),
                &action,
                target.as_deref(),
                &result,
                ip.as_deref(),
                None,
            )
        })
        .await;
}
pub async fn query(
    state: &AuthState,
    sub: Option<String>,
    action: Option<String>,
    since: Option<f64>,
    limit: u32,
) -> Result<Vec<Value>, super::error::AuthError> {
    state
        .db
        .call(move |c| store::audit_query(c, sub.as_deref(), action.as_deref(), since, limit))
        .await
}

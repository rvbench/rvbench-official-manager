//! User identity and authorization for the manager (plan 2026-10-24 用户体系, M0-M3).
//! Wire shapes follow contract/openapi.yaml; auth.sqlite is independent of the
//! ManagerData snapshot (design D9). Authorization is a route-level guard with an
//! explicit permission per business route (design D8); resource ownership
//! (owner-or-404) is checked inside handlers, where the job id is known.
pub mod audit;
pub mod config;
pub mod error;
pub mod github;
pub mod metrics;
pub mod provider;
pub mod role;
pub mod routes;
pub mod session;
pub mod static_provider;
pub mod store;

use axum::http::{HeaderMap, header};
use axum::{extract::Request, middleware::Next, response::{IntoResponse, Response}};
pub use config::{AuthConfig, ProviderConfig};
pub use error::AuthError;
use metrics::AuthMetrics;
use provider::IdentityProvider;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
pub use store::AuthDb;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Off,
    Warn,
    Enforce,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    User,
    EarlyAccess,
    Admin,
    /// Machine principal resolved from an rvbw_ token; mutually exclusive with
    /// the human roles (design §2).
    Worker,
}
impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::User => "user",
            Role::EarlyAccess => "early_access",
            Role::Admin => "admin",
            Role::Worker => "worker",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Permission {
    PublicRead,
    MetricsRead,
    JobSubmit,
    JobReadSelf,
    JobReadAll,
    JobCancelSelf,
    SuitePublish,
    SuiteRun,
    SuiteReadSelf,
    SuiteReadAll,
    SessionRevoke,
    WorkerCreateSelf,
    WorkerCreatePublic,
    WorkerRegister,
    WorkerExecute,
    WorkerManageSelf,
    WorkerManageAll,
}
impl Permission {
    pub const ALL: &'static [Permission] = &[
        Permission::PublicRead,
        Permission::MetricsRead,
        Permission::JobSubmit,
        Permission::JobReadSelf,
        Permission::JobReadAll,
        Permission::JobCancelSelf,
        Permission::SuitePublish,
        Permission::SuiteRun,
        Permission::SuiteReadSelf,
        Permission::SuiteReadAll,
        Permission::SessionRevoke,
        Permission::WorkerCreateSelf,
        Permission::WorkerCreatePublic,
        Permission::WorkerRegister,
        Permission::WorkerExecute,
        Permission::WorkerManageSelf,
        Permission::WorkerManageAll,
    ];
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::PublicRead => "public:read",
            Permission::MetricsRead => "metrics:read",
            Permission::JobSubmit => "job:submit",
            Permission::JobReadSelf => "job:read:self",
            Permission::JobReadAll => "job:read:all",
            Permission::JobCancelSelf => "job:cancel:self",
            Permission::SuitePublish => "suite:publish",
            Permission::SuiteRun => "suite:run",
            Permission::SuiteReadSelf => "suite:read:self",
            Permission::SuiteReadAll => "suite:read:all",
            Permission::SessionRevoke => "session:revoke",
            Permission::WorkerCreateSelf => "worker:create:self",
            Permission::WorkerCreatePublic => "worker:create:public",
            Permission::WorkerRegister => "worker:register",
            Permission::WorkerExecute => "worker:execute",
            Permission::WorkerManageSelf => "worker:manage:self",
            Permission::WorkerManageAll => "worker:manage:all",
        }
    }
    /// Machine-channel permissions gate /cluster/*; their enforcement is
    /// independent of auth.mode (design §2 channel switch).
    pub fn is_worker_channel(&self) -> bool {
        matches!(self, Permission::WorkerRegister | Permission::WorkerExecute)
    }
}
/// Role -> permission set (design §2 matrix). Admin accumulates every human
/// permission but never the machine ones (a person must not claim jobs as a
/// worker); the worker role gets exactly the machine channel plus self-manage.
pub fn permissions_for(roles: &[Role]) -> Vec<Permission> {
    if roles.contains(&Role::Worker) {
        return vec![
            Permission::PublicRead,
            Permission::WorkerRegister,
            Permission::WorkerExecute,
            Permission::WorkerManageSelf,
        ];
    }
    if roles.contains(&Role::Admin) {
        return Permission::ALL
            .iter()
            .copied()
            .filter(|p| !p.is_worker_channel())
            .collect();
    }
    let mut p = vec![
        Permission::PublicRead,
        Permission::MetricsRead,
        Permission::JobSubmit,
        Permission::JobReadSelf,
        Permission::JobCancelSelf,
        Permission::WorkerCreateSelf,
        Permission::WorkerManageSelf,
    ];
    if roles.contains(&Role::EarlyAccess) {
        p.extend([
            Permission::SuitePublish,
            Permission::SuiteRun,
            Permission::SuiteReadSelf,
        ]);
    }
    p
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub sub: String,
    pub login: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub provider: String,
    pub roles: Vec<Role>,
    pub permissions: Vec<Permission>,
    pub roles_stale: bool,
    pub is_admin: bool,
    pub session_kind: String,
    pub session_expires_at: f64,
    pub session_sha256: String,
}
impl Principal {
    pub fn has(&self, p: Permission) -> bool {
        self.permissions.contains(&p)
    }
    pub fn is_worker(&self) -> bool {
        self.roles.contains(&Role::Worker)
    }
}

/// In-memory token bucket, per key (login endpoints: 10/min per IP, design §6).
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    slots: Mutex<HashMap<String, (f64, f64)>>,
}
impl RateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            slots: Mutex::new(HashMap::new()),
        }
    }
    pub fn check(&self, key: &str, now: f64) -> bool {
        let mut slots = self.slots.lock().unwrap();
        let (tokens, last) = slots.get(key).copied().unwrap_or((self.capacity, now));
        let tokens = (tokens + (now - last).max(0.0) * self.refill_per_sec).min(self.capacity);
        if tokens < 1.0 {
            slots.insert(key.into(), (tokens, now));
            return false;
        }
        slots.insert(key.into(), (tokens - 1.0, now));
        true
    }
}

pub struct AuthState {
    pub config: AuthConfig,
    pub db: AuthDb,
    pub provider: Arc<dyn IdentityProvider>,
    pub admins: Vec<String>,
    pub metrics: AuthMetrics,
    pub limiter: RateLimiter,
    /// Claim endpoint budget: 5/min per IP (design §6).
    pub claim_limiter: RateLimiter,
    /// Worker records (hot path for rvbw_ auth and allocate ownership).
    pub workers: crate::workers::WorkerRegistry,
    /// register() heartbeats aggregated here; flushed to auth.sqlite every 10s.
    pub heartbeats: Mutex<BTreeMap<String, f64>>,
}
impl AuthState {
    pub async fn open(
        config: AuthConfig,
        data_dir: &Path,
        bootstrap: Vec<crate::workers::migrate::BootstrapToken>,
    ) -> anyhow::Result<Arc<Self>> {
        config.validate()?;
        let provider: Arc<dyn IdentityProvider> = match &config.provider {
            ProviderConfig::Github {
                client_id,
                client_secret_env,
                org,
                team_slug,
            } => {
                let secret = std::env::var(client_secret_env).map_err(|_| {
                    anyhow::anyhow!("auth provider needs env {client_secret_env}")
                })?;
                anyhow::ensure!(!secret.trim().is_empty(), "env {client_secret_env} is empty");
                Arc::new(github::Github::new(client_id, secret, org.clone(), team_slug.clone()))
            }
            ProviderConfig::Static { users } => {
                Arc::new(static_provider::Static::new(users.clone()))
            }
        };
        let db = AuthDb::open(&data_dir.join("auth.sqlite"))?;
        db.call(|c| crate::workers::store::init_tables(c).map_err(|e| AuthError::internal(e.to_string())))
            .await
            .map_err(|e: AuthError| anyhow::anyhow!(e.message))?;
        let workers = crate::workers::WorkerRegistry::load(&db, bootstrap).await?;
        Ok(Arc::new(Self {
            db,
            provider,
            admins: config.admins.clone(),
            metrics: AuthMetrics::default(),
            limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            claim_limiter: RateLimiter::new(5.0, 5.0 / 60.0),
            workers,
            heartbeats: Mutex::new(BTreeMap::new()),
            config,
        }))
    }
    pub fn disabled() -> Arc<Self> {
        Arc::new(Self {
            db: AuthDb::memory().expect("in-memory auth db"),
            provider: Arc::new(static_provider::Static::new(Vec::new())),
            admins: Vec::new(),
            metrics: AuthMetrics::default(),
            limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            claim_limiter: RateLimiter::new(5.0, 5.0 / 60.0),
            workers: crate::workers::WorkerRegistry::default(),
            heartbeats: Mutex::new(BTreeMap::new()),
            config: AuthConfig::default(),
        })
    }
    /// Resolves the caller from Bearer rvb_… or the rvb_session cookie. Unknown,
    /// revoked, or expired credentials resolve to anonymous (None), letting the
    /// permission layer pick 401 vs 403 (design §4.3).
    pub async fn resolve(&self, headers: &HeaderMap) -> Option<Principal> {
        let token = bearer_token(headers).or_else(|| cookie_value(headers, "rvb_session"))?;
        if token.starts_with("rvbw_") {
            // Machine channel: resolves regardless of auth.mode (design §2).
            // Stored hashes cover the full token string, prefix included.
            let record = self.workers.by_token(&session::sha256_hex(&token))?;
            let roles = vec![Role::Worker];
            let permissions = permissions_for(&roles);
            return Some(Principal {
                is_admin: false,
                permissions,
                sub: format!("worker:{}", record.worker_id),
                login: record.worker_id.clone(),
                name: None,
                avatar_url: None,
                provider: "worker".into(),
                roles,
                roles_stale: false,
                session_kind: "worker".into(),
                session_expires_at: 0.0,
                session_sha256: String::new(),
            });
        }
        if self.config.mode == AuthMode::Off {
            return None;
        }
        let sha = session::sha256_hex(&token);
        let web_ttl = self.config.session_ttl();
        let Some((session_row, principal_row)) = self
            .db
            .call(move |c| {
                let now = rvbench_protocol::seconds();
                let mut s = match store::find_session(c, &sha, now)? {
                    Some(s) => s,
                    None => return Ok(None),
                };
                if let Some(e) = store::touch_session(c, &sha, now, web_ttl)? {
                    s.expires_at = e;
                }
                match store::get_principal(c, &s.sub)? {
                    Some(p) => Ok(Some((s, p))),
                    None => Ok(None),
                }
            })
            .await
            .ok()
            .flatten()
        else {
            return None;
        };
        let (roles, stale) = role::derive(
            self,
            &principal_row.sub,
            &principal_row.login,
            session_row.provider_token.as_deref(),
        )
        .await;
        let is_admin = roles.contains(&Role::Admin);
        Some(Principal {
            is_admin,
            permissions: permissions_for(&roles),
            sub: principal_row.sub,
            login: principal_row.login,
            name: principal_row.name,
            avatar_url: principal_row.avatar_url,
            provider: principal_row.provider,
            roles,
            roles_stale: stale,
            session_kind: session_row.kind,
            session_expires_at: session_row.expires_at,
            session_sha256: session_row.token_sha256,
        })
    }
    /// Three-mode gate for business routes (design D7): off passes, warn passes and
    /// counts, enforce rejects. Ok(None) means anonymous pass-through (off/warn).
    pub async fn check(
        &self,
        headers: &HeaderMap,
        permission: Permission,
    ) -> Result<Option<Principal>, AuthError> {
        if permission.is_worker_channel() {
            // Channel switch independent of auth.mode (design §2): with no tokens
            // anywhere /cluster/* stays open (gray period); once a usable token
            // exists, machine credentials are mandatory.
            let principal = self.resolve(headers).await;
            if !self.workers.channel_active() {
                return Ok(principal);
            }
            return match principal {
                Some(p) if p.has(permission) => Ok(Some(p)),
                Some(_) => {
                    self.metrics.denied();
                    Err(AuthError::forbidden("permission denied")
                        .with_details(json!({"required": permission.as_str()})))
                }
                None => {
                    self.metrics.denied();
                    Err(AuthError::unauthenticated("worker token required"))
                }
            };
        }
        if self.config.mode == AuthMode::Off {
            return Ok(None);
        }
        match self.resolve(headers).await {
            None => {
                if self.config.mode == AuthMode::Warn {
                    self.metrics.would_deny(permission);
                    return Ok(None);
                }
                self.metrics.denied();
                Err(AuthError::unauthenticated("authentication required"))
            }
            Some(p) => {
                if p.has(permission) {
                    return Ok(Some(p));
                }
                if self.config.mode == AuthMode::Warn {
                    self.metrics.would_deny(permission);
                    return Ok(Some(p));
                }
                self.metrics.denied();
                Err(AuthError::forbidden("permission denied")
                    .with_details(json!({"required": permission.as_str()})))
            }
        }
    }
}

/// Any-authenticated-principal guard (no specific permission).
pub async fn guard_user(manager: &crate::Manager, mut req: Request, next: Next) -> Response {
    match manager.auth.resolve(req.headers()).await {
        Some(p) => {
            req.extensions_mut().insert(p);
            next.run(req).await
        }
        None => AuthError::unauthenticated("authentication required").into_response(),
    }
}

/// Route-level guard used via `axum::middleware::from_fn` in `router()`.
pub async fn guard(manager: &crate::Manager, mut req: Request, next: Next, permission: Permission) -> Response {
    match manager.auth.check(req.headers(), permission).await {
        Ok(principal) => {
            if let Some(p) = principal {
                req.extensions_mut().insert(p);
            }
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}

pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
        .filter(|t| t.starts_with("rvb_") || t.starts_with("rvbw_"))
}
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|part| {
            let (k, v) = part.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}
pub fn build_cookie(name: &str, value: &str, max_age: Option<i64>, secure: bool) -> String {
    let mut c = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax");
    if let Some(s) = max_age {
        c.push_str(&format!("; Max-Age={s}"));
    }
    if secure {
        c.push_str("; Secure");
    }
    c
}
pub fn iso(secs: f64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}
/// Login redirects accept only same-origin relative paths (design §6 open redirect).
pub fn safe_redirect(r: Option<&str>) -> Result<String, AuthError> {
    match r {
        None => Ok("/ui".into()),
        Some(p)
            if p.len() <= 512 && p.starts_with('/') && !p[1..].starts_with('/') =>
        {
            Ok(p.to_string())
        }
        _ => Err(AuthError::redirect_not_allowed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_accumulate_by_role() {
        let user = permissions_for(&[Role::User]);
        assert!(user.contains(&Permission::JobSubmit));
        assert!(!user.contains(&Permission::SuitePublish));
        let ead = permissions_for(&[Role::User, Role::EarlyAccess]);
        assert!(ead.contains(&Permission::SuitePublish) && ead.contains(&Permission::JobSubmit));
        let admin = permissions_for(&[Role::User, Role::Admin]);
        assert_eq!(
            admin,
            Permission::ALL.iter().copied().filter(|p| !p.is_worker_channel()).collect::<Vec<_>>(),
            "admin never carries the machine channel"
        );
        assert!(admin.contains(&Permission::WorkerCreatePublic));
        assert!(admin.contains(&Permission::WorkerManageAll));
        let machine = permissions_for(&[Role::Worker]);
        assert!(machine.contains(&Permission::WorkerRegister) && machine.contains(&Permission::WorkerExecute));
        assert!(!machine.contains(&Permission::JobSubmit));
        assert!(!machine.contains(&Permission::MetricsRead));
    }

    #[test]
    fn rate_limiter_bursts_then_refills() {
        let l = RateLimiter::new(3.0, 1.0);
        assert!(l.check("a", 0.0) && l.check("a", 0.1) && l.check("a", 0.2));
        assert!(!l.check("a", 0.3));
        assert!(l.check("b", 0.3), "keys are independent");
        assert!(l.check("a", 1.5), "one token refilled after 1.5s");
    }

    #[test]
    fn cookie_parsing_and_building() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "a=1; rvb_session=rvb_abc; c=2".parse().unwrap());
        assert_eq!(cookie_value(&h, "rvb_session").as_deref(), Some("rvb_abc"));
        assert_eq!(
            build_cookie("rvb_session", "v", Some(600), false),
            "rvb_session=v; Path=/; HttpOnly; SameSite=Lax; Max-Age=600"
        );
        assert!(build_cookie("s", "v", None, true).contains("; Secure"));
    }
}

//! Role derivation with cache and provider-failure degradation (design D3).
//! Not fail-open (GitHub down never grants suite permissions) and not fail-closed
//! (login-derived `user` survives); degraded entries re-probe after 60s.
use super::provider::Membership;
use super::store;
use super::{AuthState, Role};

pub async fn derive(
    state: &AuthState,
    sub: &str,
    login: &str,
    provider_token: Option<&str>,
) -> (Vec<Role>, bool) {
    let mut roles = vec![Role::User];
    if state.admins.iter().any(|a| a == sub) {
        roles.push(Role::Admin);
    }
    let (sub, login, token) = (sub.to_string(), login.to_string(), provider_token.map(str::to_string));
    let ttl = state.config.role_cache_ttl();
    let sub_for_get = sub.clone();
    match state.db.call(move |c| store::cache_get(c, &sub_for_get, rvbench_protocol::seconds())).await {
        Ok(Some((early, degraded))) => {
            if early {
                roles.push(Role::EarlyAccess);
            }
            (roles, degraded)
        }
        _ => {
            let membership = state
                .provider
                .team_membership(token, login.clone())
                .await;
            match membership {
                Ok(Membership::Active) => {
                    let _ = state
                        .db.call(move |c| store::cache_put(c, &sub, true, false, rvbench_protocol::seconds(), ttl))
                        .await;
                    roles.push(Role::EarlyAccess);
                    (roles, false)
                }
                Ok(_) => {
                    let _ = state
                        .db.call(move |c| store::cache_put(c, &sub, false, false, rvbench_protocol::seconds(), ttl))
                        .await;
                    (roles, false)
                }
                // Provider unavailable: keep `user`, drop early_access, retry in 60s.
                Err(_) => {
                    let _ = state
                        .db.call(move |c| store::cache_put(c, &sub, false, true, rvbench_protocol::seconds(), 60.0))
                        .await;
                    (roles, true)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::config::{AuthConfig, ProviderConfig};
    use crate::auth::metrics::AuthMetrics;
    use crate::auth::provider::{FailingProvider, IdentityProvider, static_user};
    use crate::auth::{AuthDb, AuthMode, AuthState, RateLimiter};
    use std::sync::Arc;

    async fn state_with(provider: Arc<dyn IdentityProvider>, users: Vec<crate::auth::config::StaticUser>) -> (tempfile::TempDir, Arc<AuthState>) {
        let t = tempfile::tempdir().unwrap();
        let s = AuthState {
            config: AuthConfig {
                mode: AuthMode::Enforce,
                provider: ProviderConfig::Static { users },
                ..Default::default()
            },
            db: AuthDb::open(&t.path().join("auth.sqlite")).unwrap(),
            provider,
            admins: vec!["github:9".into()],
            metrics: AuthMetrics::default(),
            limiter: RateLimiter::new(1e9, 1e9),
            claim_limiter: RateLimiter::new(1e9, 1e9),
            workers: crate::workers::WorkerRegistry::default(),
            heartbeats: std::sync::Mutex::new(Default::default()),
        };
        (t, Arc::new(s))
    }

    #[tokio::test]
    async fn early_access_follows_team_membership_and_cache() {
        let users = vec![static_user("alice", 1, Some("earlyaccessdevelopers")), static_user("bob", 2, None)];
        let (_t, s) = state_with(Arc::new(crate::auth::static_provider::Static::new(users.clone())), users).await;
        let (roles, stale) = derive(&s, "github:1", "alice", None).await;
        assert_eq!(roles, vec![Role::User, Role::EarlyAccess]);
        assert!(!stale);
        let (roles, _) = derive(&s, "github:2", "bob", None).await;
        assert_eq!(roles, vec![Role::User]);
        // Admin is config-derived, independent of the provider.
        let (roles, _) = derive(&s, "github:9", "root", None).await;
        assert_eq!(roles, vec![Role::User, Role::Admin]);
    }

    #[tokio::test]
    async fn provider_failure_degrades_to_user_and_marks_stale() {
        let (_t, s) = state_with(Arc::new(FailingProvider), vec![]).await;
        let (roles, stale) = derive(&s, "github:1", "alice", Some("tok")).await;
        assert_eq!(roles, vec![Role::User]);
        assert!(stale, "degradation must be visible to /auth/me");
        // The degraded entry is served from cache for the next 60s.
        let (roles, stale) = derive(&s, "github:1", "alice", Some("tok")).await;
        assert_eq!(roles, vec![Role::User]);
        assert!(stale);
    }
}

//! Provider abstraction shaped like OIDC; GitHub is the first adapter (design D2).
//! Boxed futures keep the trait object-safe without async-trait.
use base64::Engine;
use super::{config::StaticUser, error::AuthError};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin, sync::Arc};

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Clone)]
pub struct Pkce {
    pub verifier: String,
}
impl Pkce {
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self {
            verifier: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        }
    }
    pub fn challenge(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(self.verifier.as_bytes()))
    }
}
#[derive(Clone, Debug)]
pub struct ProviderUser {
    pub sub: String,
    pub login: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Membership {
    Active,
    Pending,
    Absent,
}

pub trait IdentityProvider: Send + Sync {
    fn kind(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn authorize_url(&self, state: &str, pkce: &Pkce, redirect_uri: &str) -> String;
    fn exchange_code(&self, code: String, pkce: Pkce, redirect_uri: String) -> BoxFut<Result<String, AuthError>>;
    fn userinfo(&self, token: String) -> BoxFut<Result<ProviderUser, AuthError>>;
    /// GitHub answers team membership only for the token owner; `token` is the
    /// provider access token and `login` is only used by config-backed providers.
    fn team_membership(&self, token: Option<String>, login: String) -> BoxFut<Result<Membership, AuthError>>;
}

/// Test-only provider that always fails; used to exercise role degradation (D3).
pub struct FailingProvider;
impl IdentityProvider for FailingProvider {
    fn kind(&self) -> &'static str {
        "static"
    }
    fn display_name(&self) -> &'static str {
        "Failing"
    }
    fn authorize_url(&self, _: &str, _: &Pkce, _: &str) -> String {
        String::new()
    }
    fn exchange_code(&self, _: String, _: Pkce, _: String) -> BoxFut<Result<String, AuthError>> {
        Box::pin(async { Err(AuthError::provider_unavailable("failing provider")) })
    }
    fn userinfo(&self, _: String) -> BoxFut<Result<ProviderUser, AuthError>> {
        Box::pin(async { Err(AuthError::provider_unavailable("failing provider")) })
    }
    fn team_membership(&self, _: Option<String>, _: String) -> BoxFut<Result<Membership, AuthError>> {
        Box::pin(async { Err(AuthError::provider_unavailable("failing provider")) })
    }
}

pub fn static_user(login: &str, id: u64, team: Option<&str>) -> StaticUser {
    StaticUser {
        login: login.into(),
        id,
        name: None,
        team: team.map(str::to_string),
    }
}
pub fn provider_arc(p: impl IdentityProvider + 'static) -> Arc<dyn IdentityProvider> {
    Arc::new(p)
}

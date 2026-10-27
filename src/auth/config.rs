//! Auth configuration and startup validation (design §5.3).
use super::AuthMode;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub provider: ProviderConfig,
    pub admins: Vec<String>,
    pub public_base_url: Option<String>,
    pub session_ttl_hours: Option<u64>,
    pub cli_token_ttl_days: Option<u64>,
    pub role_cache_seconds: Option<u64>,
    pub allow_insecure_cookie: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ProviderConfig {
    Github {
        client_id: String,
        client_secret_env: String,
        org: String,
        team_slug: String,
    },
    Static {
        #[serde(default)]
        users: Vec<StaticUser>,
    },
}
impl Default for ProviderConfig {
    fn default() -> Self {
        Self::Static { users: Vec::new() }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticUser {
    pub login: String,
    pub id: u64,
    pub name: Option<String>,
    pub team: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}
impl AuthConfig {
    pub fn session_ttl(&self) -> f64 {
        self.session_ttl_hours.unwrap_or(12) as f64 * 3600.0
    }
    pub fn cli_ttl(&self) -> f64 {
        self.cli_token_ttl_days.unwrap_or(30) as f64 * 86400.0
    }
    pub fn role_cache_ttl(&self) -> f64 {
        self.role_cache_seconds.unwrap_or(300) as f64
    }
    pub fn base_url(&self) -> Option<reqwest::Url> {
        self.public_base_url
            .as_deref()
            .and_then(|u| reqwest::Url::parse(u).ok())
    }
    pub fn cookie_secure(&self) -> bool {
        self.base_url().is_some_and(|u| u.scheme() == "https")
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.mode == AuthMode::Off {
            return Ok(());
        }
        let Some(base) = &self.public_base_url else {
            anyhow::bail!("auth.mode != off requires public_base_url");
        };
        let url = reqwest::Url::parse(base)?;
        let loopback = matches!(
            url.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        );
        match (url.scheme(), loopback, self.allow_insecure_cookie) {
            ("https", _, _) => {}
            ("http", true, _) => {}
            ("http", false, true) => {}
            _ => anyhow::bail!(
                "public_base_url must be https, http on loopback, or http with allow_insecure_cookie"
            ),
        }
        for a in &self.admins {
            let id = a.strip_prefix("github:").unwrap_or_default();
            anyhow::ensure!(
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
                "admins entries must match github:<digits>, got {a}"
            );
        }
        if let ProviderConfig::Github {
            client_id,
            client_secret_env,
            ..
        } = &self.provider
        {
            anyhow::ensure!(!client_id.is_empty(), "github provider requires client_id");
            anyhow::ensure!(
                !client_secret_env.is_empty(),
                "github provider requires client_secret_env"
            );
        }
        Ok(())
    }
}

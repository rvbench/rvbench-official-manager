//! Config-fixed provider for tests and local development (design D12).
//! `access_token` is simply the configured login.
use super::config::StaticUser;
use super::error::AuthError;
use super::provider::{BoxFut, IdentityProvider, Membership, Pkce, ProviderUser};

pub struct Static {
    users: Vec<StaticUser>,
    team_slug: String,
}
impl Static {
    pub fn new(users: Vec<StaticUser>) -> Self {
        Self {
            users,
            team_slug: "earlyaccessdevelopers".into(),
        }
    }
    fn find(&self, login: &str) -> Option<&StaticUser> {
        self.users.iter().find(|u| u.login == login)
    }
}
impl IdentityProvider for Static {
    fn kind(&self) -> &'static str {
        "static"
    }
    fn display_name(&self) -> &'static str {
        "Static"
    }
    fn authorize_url(&self, _: &str, _: &Pkce, _: &str) -> String {
        // Browser login against the static provider is handled by /auth/login
        // itself (?login=<name>); there is no external authorize step.
        String::new()
    }
    fn exchange_code(&self, _: String, _: Pkce, _: String) -> BoxFut<Result<String, AuthError>> {
        Box::pin(async {
            Err(AuthError::state_invalid(
                "static provider has no code exchange",
            ))
        })
    }
    fn userinfo(&self, token: String) -> BoxFut<Result<ProviderUser, AuthError>> {
        let found = self.find(&token).map(|u| ProviderUser {
            sub: format!("github:{}", u.id),
            login: u.login.clone(),
            name: u.name.clone(),
            email: u.email.clone(),
            avatar_url: u.avatar_url.clone(),
        });
        Box::pin(async move {
            found.ok_or_else(|| AuthError::grant_invalid(format!("unknown static user {token}")))
        })
    }
    fn team_membership(
        &self,
        _token: Option<String>,
        login: String,
    ) -> BoxFut<Result<Membership, AuthError>> {
        let hit = self
            .find(&login)
            .and_then(|u| u.team.as_deref())
            .is_some_and(|t| t.eq_ignore_ascii_case(&self.team_slug));
        Box::pin(async move {
            Ok(if hit {
                Membership::Active
            } else {
                Membership::Absent
            })
        })
    }
}

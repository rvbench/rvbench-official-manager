//! GitHub OAuth2 adapter: authorize / exchange / userinfo / teams (design §4.1).
//! Base URLs are fields so tests can point the adapter at a local mock.
use super::provider::{BoxFut, IdentityProvider, Membership, Pkce, ProviderUser};
use super::error::AuthError;
use serde_json::Value;

pub struct Github {
    client_id: String,
    client_secret: String,
    org: String,
    team_slug: String,
    authorize_base: String,
    token_base: String,
    api_base: String,
}
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
fn http() -> reqwest::Client {
    reqwest::Client::builder().timeout(TIMEOUT).build().unwrap_or_default()
}
fn map_error(e: reqwest::Error) -> AuthError {
    AuthError::provider_unavailable(format!("github request failed: {e}"))
}
impl Github {
    pub fn new(client_id: &str, client_secret: String, org: String, team_slug: String) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            org,
            team_slug,
            authorize_base: "https://github.com/login/oauth/authorize".into(),
            token_base: "https://github.com/login/oauth/access_token".into(),
            api_base: "https://api.github.com".into(),
        }
    }
    async fn get_json(url: String, token: &str) -> Result<Value, AuthError> {
        let r = http()
            .get(&url)
            .header(reqwest::header::USER_AGENT, "rvbench-manager")
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(map_error)?;
        match r.status() {
            s if s.is_success() => r.json::<Value>().await.map_err(map_error),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                Err(AuthError::grant_invalid("github rejected the token"))
            }
            s => Err(AuthError::provider_unavailable(format!("github returned {s}"))),
        }
    }
}
impl IdentityProvider for Github {
    fn kind(&self) -> &'static str {
        "github"
    }
    fn display_name(&self) -> &'static str {
        "GitHub"
    }
    fn authorize_url(&self, state: &str, pkce: &Pkce, redirect_uri: &str) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&scope=read%3Auser%20read%3Aorg&state={}&code_challenge={}&code_challenge_method=S256",
            self.authorize_base,
            self.client_id,
            urlencode(redirect_uri),
            urlencode(state),
            pkce.challenge()
        )
    }
    fn exchange_code(&self, code: String, pkce: Pkce, redirect_uri: String) -> BoxFut<Result<String, AuthError>> {
        let (url, id, secret) =
            (self.token_base.clone(), self.client_id.clone(), self.client_secret.clone());
        Box::pin(async move {
            let r = http()
                .post(url)
                .header(reqwest::header::ACCEPT, "application/json")
                .form(&[
                    ("client_id", id.as_str()),
                    ("client_secret", secret.as_str()),
                    ("code", code.as_str()),
                    ("redirect_uri", redirect_uri.as_str()),
                    ("code_verifier", pkce.verifier.as_str()),
                ])
                .send()
                .await
                .map_err(map_error)?;
            if !r.status().is_success() {
                return Err(AuthError::grant_invalid("github rejected the code"));
            }
            let v: Value = r.json().await.map_err(map_error)?;
            v["access_token"]
                .as_str()
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .ok_or_else(|| AuthError::grant_invalid("github returned no access_token"))
        })
    }
    fn userinfo(&self, token: String) -> BoxFut<Result<ProviderUser, AuthError>> {
        let url = format!("{}/user", self.api_base);
        Box::pin(async move {
            let v = Self::get_json(url, &token).await?;
            let id = v["id"]
                .as_u64()
                .ok_or_else(|| AuthError::provider_unavailable("github userinfo missing numeric id"))?;
            Ok(ProviderUser {
                sub: format!("github:{id}"),
                login: v["login"].as_str().unwrap_or_default().to_string(),
                name: v["name"].as_str().map(str::to_string),
                email: v["email"].as_str().map(str::to_string),
                avatar_url: v["avatar_url"].as_str().map(str::to_string),
            })
        })
    }
    fn team_membership(&self, token: Option<String>, _login: String) -> BoxFut<Result<Membership, AuthError>> {
        let Some(token) = token else {
            return Box::pin(async { Err(AuthError::provider_unavailable("no provider token for team lookup")) });
        };
        let url_base = self.api_base.clone();
        let (org, team) = (self.org.clone(), self.team_slug.clone());
        Box::pin(async move {
            for page in 1..=5 {
                let v = Self::get_json(format!("{url_base}/user/teams?per_page=100&page={page}"), &token).await?;
                let Some(teams) = v.as_array() else { return Ok(Membership::Absent) };
                for t in teams {
                    if t["org"]["login"].as_str() == Some(org.as_str())
                        && t["slug"].as_str() == Some(team.as_str())
                    {
                        return Ok(match t["state"].as_str() {
                            Some("active") => Membership::Active,
                            Some("pending") => Membership::Pending,
                            _ => Membership::Absent,
                        });
                    }
                }
                if teams.len() < 100 {
                    return Ok(Membership::Absent);
                }
            }
            // Over 500 teams: treat as absent rather than guess (design §4.1).
            Ok(Membership::Absent)
        })
    }
}
pub fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::Query, routing::{get, post}};
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn authorize_url_carries_scope_state_and_pkce() {
        let g = Github::new("cid", "secret".into(), "rvbench".into(), "earlyaccessdevelopers".into());
        let pkce = Pkce::new();
        let url = g.authorize_url("st-ate", &pkce, "https://rvbench.hk.c4y.dev/auth/callback");
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(url.contains("client_id=cid"));
        assert!(url.contains("scope=read%3Auser%20read%3Aorg"));
        assert!(url.contains("state=st-ate"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(&urlencode("https://rvbench.hk.c4y.dev/auth/callback")));
    }

    #[tokio::test]
    async fn exchange_userinfo_and_paginated_teams_against_a_local_mock() {
        let app = Router::new()
            .route(
                "/login/oauth/access_token",
                post(|| async { Json(json!({"access_token":"gho_ok","token_type":"bearer"})) }),
            )
            .route(
                "/user",
                get(|| async { Json(json!({"id":1234567,"login":"c4y","name":"C4Y","avatar_url":"https://a/1.png"})) }),
            )
            .route(
                "/user/teams",
                get(|Query(q): Query<HashMap<String, String>>| async move {
                    let page: usize = q.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
                    // Page 1: 100 unrelated teams. Page 2: the match.
                    let items = if page == 1 {
                        (0..100)
                            .map(|i| json!({"org":{"login":"other-org"},"slug":format!("team-{i}"),"state":"active"}))
                            .collect()
                    } else {
                        vec![json!({"org":{"login":"rvbench"},"slug":"earlyaccessdevelopers","state":"active"})]
                    };
                    Json(items)
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, app).into_future());
        let mut g = Github::new("cid", "secret".into(), "rvbench".into(), "earlyaccessdevelopers".into());
        g.token_base = format!("{base}/login/oauth/access_token");
        g.api_base = base.clone();
        let token = g.exchange_code("the-code".into(), Pkce::new(), "https://example/cb".into()).await.unwrap();
        assert_eq!(token, "gho_ok");
        let user = g.userinfo(token.clone()).await.unwrap();
        assert_eq!(user.sub, "github:1234567");
        assert_eq!(user.login, "c4y");
        assert_eq!(g.team_membership(Some(token), "c4y".into()).await.unwrap(), Membership::Active);
        assert_eq!(g.team_membership(None, "c4y".into()).await.unwrap_err().code, "provider_unavailable");
    }

    #[tokio::test]
    async fn provider_5xx_and_rejection_map_to_contract_errors() {
        let down_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let down_base = format!("http://{}", down_listener.local_addr().unwrap());
        tokio::spawn(axum::serve(
            down_listener,
            Router::new().route("/user", get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR })),
        ).into_future());
        let mut g = Github::new("cid", "secret".into(), "rvbench".into(), "t".into());
        g.api_base = down_base;
        let down = g.userinfo("tok".into()).await.unwrap_err();
        assert_eq!(down.status, axum::http::StatusCode::BAD_GATEWAY);
        assert_eq!(down.code, "provider_unavailable");

        let rejected_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rejected_base = format!("http://{}", rejected_listener.local_addr().unwrap());
        tokio::spawn(axum::serve(
            rejected_listener,
            Router::new().route("/user", get(|| async { axum::http::StatusCode::UNAUTHORIZED })),
        ).into_future());
        let mut g2 = Github::new("cid", "secret".into(), "rvbench".into(), "t".into());
        g2.api_base = rejected_base;
        let rejected = g2.userinfo("tok".into()).await.unwrap_err();
        assert_eq!(rejected.status, axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(rejected.code, "grant_invalid");
    }
}

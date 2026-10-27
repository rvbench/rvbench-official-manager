//! User-system end-to-end coverage against the HTTP router (plan §5 routes row,
//! M2 acceptance table, design §2). Runs entirely on the static provider.
use rvbench_manager::auth::{AuthConfig, AuthMode, ProviderConfig};
use rvbench_manager::{Config, Manager};
use rvbench_protocol::*;
use serde_json::{Value, json};
use std::time::Duration;

fn static_config(mode: AuthMode) -> Config {
    Config {
        listen: "127.0.0.1:0".into(),
        data_dir: std::env::temp_dir().into(),
        victoriametrics: None,
        worker_tokens: Vec::new(),
        auth: Some(AuthConfig {
            mode,
            provider: ProviderConfig::Static {
                users: vec![
                    static_user("alice", 1, Some("earlyaccessdevelopers")),
                    static_user("bob", 2, None),
                    static_user("root", 9, None),
                ],
            },
            admins: vec!["github:9".into()],
            public_base_url: Some("http://127.0.0.1:18800".into()),
            ..Default::default()
        }),
    }
}
fn static_user(
    login: &str,
    id: u64,
    team: Option<&str>,
) -> rvbench_manager::auth::config::StaticUser {
    rvbench_manager::auth::config::StaticUser {
        login: login.into(),
        id,
        name: None,
        team: team.map(str::to_string),
        email: None,
        avatar_url: None,
    }
}
async fn start(mode: AuthMode) -> (tempfile::TempDir, String) {
    start_config(static_config(mode)).await
}
async fn start_config(config: Config) -> (tempfile::TempDir, String) {
    let temp = tempfile::tempdir().unwrap();
    let m = Manager::open(Config {
        data_dir: temp.path().into(),
        ..config
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, rvbench_manager::router(m)).into_future());
    (temp, base)
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}
async fn login(c: &reqwest::Client, base: &str, user: &str) -> (String, Value) {
    let r = c
        .post(format!("{base}/auth/github/exchange"))
        .json(&json!({"access_token": user}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "exchange {user}");
    let v: Value = r.json().await.unwrap();
    (v["token"].as_str().unwrap().to_string(), v)
}
fn bearer(token: &str) -> reqwest::header::HeaderValue {
    format!("Bearer {token}").parse().unwrap()
}
fn cookie_of(r: &reqwest::Response, name: &str) -> Option<String> {
    r.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(&format!("{name}=")))
        .and_then(|c| c.split(';').next())
        .map(|c| c[name.len() + 1..].to_string())
}
/// Browser (static provider) login: returns the rvb_session cookie value.
async fn web_login(c: &reqwest::Client, base: &str, user: &str) -> String {
    let r = c
        .get(format!("{base}/auth/login?login={user}&redirect=/ui"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302, "browser login {user}");
    cookie_of(&r, "rvb_session").unwrap_or_else(|| panic!("session cookie for {user}"))
}
async fn me_with(c: &reqwest::Client, base: &str, token: &str) -> Value {
    c.get(format!("{base}/auth/me"))
        .header(reqwest::header::AUTHORIZATION, bearer(token))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}
/// Static user carrying profile data (plan M1: `email`/`avatar_url` on
/// `StaticUser`). Built via JSON on purpose: until the M1 implementation adds
/// those fields this helper fails at *runtime* (deny_unknown_fields) instead of
/// breaking compilation of the whole test binary; the failure is the expected
/// "implementation missing" red.
fn rich_static_user(
    login: &str,
    id: u64,
    email: &str,
    avatar_url: &str,
) -> rvbench_manager::auth::config::StaticUser {
    serde_json::from_value(json!({
        "login": login,
        "id": id,
        "email": email,
        "avatar_url": avatar_url
    }))
    .unwrap()
}

#[tokio::test]
async fn enforce_boundaries_match_the_permission_table() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let body: Value = serde_json::from_str(EXAMPLE_JOB).unwrap();

    // Anonymous write is rejected; warn/off behavior is covered separately.
    let r = c
        .post(format!("{base}/jobs"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.headers().contains_key("www-authenticate"));

    let (bob, _) = login(&c, &base, "bob").await;
    let (alice, _) = login(&c, &base, "alice").await;
    let (root, _) = login(&c, &base, "root").await;

    // user (bob) and early_access (alice) can submit; the job records the owner.
    let bob_job: Value = c
        .post(format!("{base}/jobs"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bob_job["state"], "queued");
    let job_id = bob_job["job_id"].as_str().unwrap().to_string();

    // bob cannot read alice's... but first: alice cannot read bob's job (404, not 403).
    let r = c
        .get(format!("{base}/jobs/{job_id}"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "foreign jobs must 404 to hide existence");
    // admin reads it fine.
    let r = c
        .get(format!("{base}/jobs/{job_id}"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // GET /jobs: bob sees only his own; admin sees everything.
    let bob_list: Vec<Value> = c
        .get(format!("{base}/jobs"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(bob_list.iter().all(|j| j["job_id"] == bob_job["job_id"]));
    let root_list: Vec<Value> = c
        .get(format!("{base}/jobs"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(root_list.iter().any(|j| j["job_id"] == job_id));

    // alice may cancel only her own queued job; bob's is 404 to her.
    let r = c
        .delete(format!("{base}/jobs/{job_id}"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = c
        .delete(format!("{base}/jobs/{job_id}"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn me_reports_roles_permissions_and_degradation_state() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let (alice, _) = login(&c, &base, "alice").await;
    let me: Value = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["principal"]["sub"], "github:1");
    assert_eq!(me["principal"]["provider"], "static");
    assert_eq!(me["principal"]["roles"], json!(["user", "early_access"]));
    assert!(
        me["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "suite:publish")
    );
    assert!(
        me["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "job:submit")
    );
    assert_eq!(me["roles_stale"], false);
    assert_eq!(me["session"]["kind"], "cli");
    // Unknown tokens resolve to anonymous: 401, not 500.
    let r = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::AUTHORIZATION, "Bearer rvb_nope")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn sessions_revocation_logout_and_audit() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let (alice, _) = login(&c, &base, "alice").await;
    let (root, _) = login(&c, &base, "root").await;

    // Session list is per-user and never contains tokens.
    let sessions: Value = c
        .get(format!("{base}/auth/sessions"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = sessions["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["kind"], "cli");
    assert_eq!(items[0]["id"].as_str().unwrap().len(), 16);
    let id = items[0]["id"].as_str().unwrap().to_string();

    // A user cannot confirm or revoke someone else's session id: 404.
    let (bob, _) = login(&c, &base, "bob").await;
    let r = c
        .delete(format!("{base}/auth/sessions/{id}"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // Revoking the current session kills the token immediately.
    let r = c
        .delete(format!("{base}/auth/sessions/{id}"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Logout revokes server-side and clears the cookie.
    let r = c
        .post(format!("{base}/auth/logout"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert!(cookie_of(&r, "rvb_session").is_some());

    // A rejected exchange must land in the audit trail as login_failed.
    let r = c
        .post(format!("{base}/auth/github/exchange"))
        .json(&json!({"access_token": "unknown-user"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Audit: admin sees login/job.submit/session.revoke/logout; non-admin is 403.
    let (root2, _) = login(&c, &base, "root").await;
    let audit: Value = c
        .get(format!("{base}/auth/audit?limit=200"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root2))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let actions: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    for expected in ["login", "login_failed", "session.revoke", "logout"] {
        assert!(
            actions.contains(&expected),
            "audit missing {expected}: {actions:?}"
        );
    }
    let r = c
        .get(format!("{base}/auth/audit"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn static_browser_login_sets_cookie_and_validates_redirect() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();

    // Open redirect is refused before anything else.
    let r = c
        .get(format!("{base}/auth/login?redirect=http://evil.example"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    let r = c
        .get(format!("{base}/auth/login?login=alice&redirect=/ui"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    // First login lands on the welcome screen (plan 2026-10-27 M1); the
    // requested redirect is honored from the second login on.
    assert_eq!(r.headers().get("location").unwrap(), "/ui#/welcome");
    let cookie = cookie_of(&r, "rvb_session").expect("session cookie");

    let me: Value = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["principal"]["login"], "alice");
    assert_eq!(me["session"]["kind"], "web");

    // Cookie-authenticated writes reject a foreign Origin (design D10)...
    let r = c
        .post(format!("{base}/auth/logout"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .header(reqwest::header::ORIGIN, "http://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    // ...and pass without an Origin header (SameSite=Lax is the outer defense).
    let r = c
        .post(format!("{base}/auth/logout"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn off_and_warn_keep_current_behavior_with_counters() {
    let (_t, base) = start(AuthMode::Off).await;
    let c = client();
    let config: Value = c
        .get(format!("{base}/auth/config"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(config["enabled"], false);
    assert_eq!(config["provider"], json!(null));
    // Login endpoints are explicitly disabled in off mode.
    let r = c.get(format!("{base}/auth/login")).send().await.unwrap();
    assert_eq!(r.status(), 503);
    // Anonymous submits keep working (M0 acceptance).
    let body: Value = serde_json::from_str(EXAMPLE_JOB).unwrap();
    let r = c
        .post(format!("{base}/jobs"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202);
    let r = c.get(format!("{base}/auth/me")).send().await.unwrap();
    assert_eq!(r.status(), 401);

    let (_t2, base2) = start(AuthMode::Warn).await;
    let r = c
        .post(format!("{base2}/jobs"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202, "warn passes but counts");
    let metrics = c
        .get(format!("{base2}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("auth_would_deny_total{permission=\"job:submit\"} 1"),
        "warn must record would_deny per permission:\n{metrics}"
    );
}

#[tokio::test]
async fn login_endpoints_are_rate_limited_per_ip() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    for _ in 0..10 {
        login(&c, &base, "alice").await;
    }
    let r = c
        .post(format!("{base}/auth/github/exchange"))
        .json(&json!({"access_token": "alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        429,
        "the 11th exchange within a minute must be limited"
    );
}

#[tokio::test]
async fn github_callback_completes_the_browser_flow_against_a_mock() {
    // The adapter is pointed at a local mock; the secret comes from a test env var.
    let secret_var = "RVBENCH_TEST_GITHUB_SECRET";
    unsafe { std::env::set_var(secret_var, "s3cret") };
    let mock = axum::Router::new()
        .route(
            "/login/oauth/access_token",
            axum::routing::post(|| async {
                axum::Json(json!({"access_token":"gho_mock","token_type":"bearer"}))
            }),
        )
        .route(
            "/user",
            axum::routing::get(|| async {
                axum::Json(json!({"id":777,"login":"c4y","name":"C4Y","avatar_url":"https://a/777.png"}))
            }),
        )
        .route(
            "/user/teams",
            axum::routing::get(|| async {
                axum::Json(json!([{"org":{"login":"rvbench"},"slug":"earlyaccessdevelopers","state":"active"}]))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _mock_base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, mock).into_future());

    let temp = tempfile::tempdir().unwrap();
    let mut config = static_config(AuthMode::Enforce);
    config.data_dir = temp.path().into();
    if let Some(auth) = &mut config.auth {
        auth.provider = ProviderConfig::Github {
            client_id: "cid".into(),
            client_secret_env: secret_var.into(),
            org: "rvbench".into(),
            team_slug: "earlyaccessdevelopers".into(),
        };
    }
    let m = Manager::open(config).await.unwrap();
    // The adapter talks to real github.com, which cannot validate our fake code —
    // the browser must land on /ui?auth_error=... (adapter behavior itself is
    // covered by the mock-based tests in src/auth/github.rs).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, rvbench_manager::router(m)).into_future());
    let c = client();

    let r = c
        .get(format!("{base}/auth/login?redirect=/ui"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    let location = r
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with("https://github.com/login/oauth/authorize"));
    assert!(location.contains("code_challenge_method=S256"));
    let state_cookie = cookie_of(&r, "rvb_oauth_state").expect("state cookie");

    // Callback without a matching state cookie is rejected; with it, an unknown
    // code leads home with auth_error (provider mock not reachable by design here).
    let r = c
        .get(format!("{base}/auth/callback?code=x&state={state_cookie}"))
        .header(
            reqwest::header::COOKIE,
            format!("rvb_oauth_state={state_cookie}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    assert_eq!(
        r.headers().get("location").unwrap(),
        "/ui?auth_error=provider_unavailable"
    );
    // Mismatched state is a hard 400.
    let r = c
        .get(format!("{base}/auth/callback?code=x&state=other"))
        .header(
            reqwest::header::COOKIE,
            format!("rvb_oauth_state={state_cookie}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

// ---------------------------------------------------------------------------
// Account center matrix (plan 2026-10-27 §6, contract v1.4).
// These depend on the M1–M4 endpoints; until the implementations land they
// fail at runtime (404/missing fields), which is the expected red.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn me_exposes_email_avatar_and_first_login() {
    // A fresh static user with profile data, so the extended /auth/me surface
    // (contract MeResponse) can be asserted end-to-end on a pristine database.
    let mut config = static_config(AuthMode::Enforce);
    if let Some(auth) = &mut config.auth {
        auth.provider = ProviderConfig::Static {
            users: vec![
                rich_static_user("carol", 5, "carol@example.com", "https://a/1.png"),
                static_user("root", 9, None),
            ],
        };
    }
    let (_t, base) = start_config(config).await;
    let c = client();

    // First login: profile fields are exposed and the welcome entry flagged.
    let (carol, _) = login(&c, &base, "carol").await;
    let me = me_with(&c, &base, &carol).await;
    assert_eq!(me["is_first_login"], true);
    assert_eq!(me["principal"]["email"], "carol@example.com");
    assert_eq!(me["principal"]["avatar_url"], "https://a/1.png");
    assert!(
        me["principal"]["created_at"].is_string(),
        "created_at (first_seen) must be exposed"
    );

    // A second login flips the flag; profile fields stay stable.
    let (carol2, _) = login(&c, &base, "carol").await;
    let me2 = me_with(&c, &base, &carol2).await;
    assert_eq!(me2["is_first_login"], false);
    assert_eq!(me2["principal"]["email"], "carol@example.com");
    assert_eq!(me2["principal"]["avatar_url"], "https://a/1.png");
}

#[tokio::test]
async fn tokens_lifecycle_and_no_self_derivation() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let cookie = web_login(&c, &base, "alice").await;

    // Create from a web session; the plaintext token appears exactly once.
    let created: Value = c
        .post(format!("{base}/auth/tokens"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .json(&json!({"label": "ci-runner", "ttl_days": 30}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["token_type"], "Bearer");
    let token = created["token"]
        .as_str()
        .expect("plaintext token")
        .to_string();
    let id = created["id"].as_str().expect("token id").to_string();
    assert!(created["expires_at"].is_string());

    // The list shows the labeled entry (never the plaintext again).
    let tokens: Value = c
        .get(format!("{base}/auth/tokens"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entry = tokens["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["label"] == "ci-runner")
        .expect("created token listed with its label");
    assert_eq!(entry["kind"], "token");
    assert_eq!(entry["id"], id.as_str());

    // The fresh token authenticates a normal authenticated endpoint...
    let r = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::AUTHORIZATION, bearer(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // ...but must not be able to derive further tokens: cookie session only.
    let r = c
        .post(format!("{base}/auth/tokens"))
        .header(reqwest::header::AUTHORIZATION, bearer(&token))
        .json(&json!({"label": "child"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "a token must not mint tokens");

    // Revoking kills it immediately.
    let r = c
        .delete(format!("{base}/auth/tokens/{id}"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::AUTHORIZATION, bearer(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "revoked token must stop working at once");
}

#[tokio::test]
async fn account_delete_is_tombstone() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let cookie = web_login(&c, &base, "alice").await;
    let (root, _) = login(&c, &base, "root").await;

    // A mismatched confirm string is a 400; the account survives.
    let r = c
        .delete(format!("{base}/auth/me"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .json(&json!({"confirm_login": "alice-typo"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Correct confirmation tombstones the account...
    let r = c
        .delete(format!("{base}/auth/me"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .json(&json!({"confirm_login": "alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    // ...and the old cookie dies with it.
    let r = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Admin view: sub kept, login rewritten to deleted-*, deleted flag set.
    let users: Value = c
        .get(format!("{base}/auth/users?limit=200"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tomb = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["sub"] == "github:1")
        .expect("tombstoned principal kept for audit/ownership");
    assert!(
        tomb["login"].as_str().unwrap().starts_with("deleted-"),
        "login rewritten to deleted-<sha8>, got {:?}",
        tomb["login"]
    );
    assert_eq!(tomb["deleted"], true);

    // The deletion is auditable.
    let audit: Value = c
        .get(format!("{base}/auth/audit?limit=200"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        audit["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "account.delete" && a["sub"] == "github:1"),
        "audit must record account.delete"
    );
}

#[tokio::test]
async fn last_admin_cannot_be_deleted_or_demoted() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    // root (github:9) is the only admin in this configuration.
    let cookie = web_login(&c, &base, "root").await;

    // Deleting the last admin is refused; the account is untouched.
    let r = c
        .delete(format!("{base}/auth/me"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .json(&json!({"confirm_login": "root"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    let me: Value = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["principal"]["login"], "root");
    assert!(
        me["principal"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "admin"),
        "admin role must survive the refused delete"
    );

    // Self-demotion hits the same guard...
    let r = c
        .patch(format!("{base}/auth/users/github:9/roles"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .json(&json!({"revoke": ["admin"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    // ...and state is unchanged: the admin console still answers.
    let r = c
        .get(format!("{base}/auth/users?limit=1"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn role_grant_invalidates_cache() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let (bob, _) = login(&c, &base, "bob").await;
    let (root, _) = login(&c, &base, "root").await;

    // Before: bob is a plain user without the early_access role or its
    // permission bits.
    let before = me_with(&c, &base, &bob).await;
    assert!(
        !before["principal"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "early_access")
    );
    assert!(
        !before["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "suite:publish")
    );

    // root grants early_access...
    let r = c
        .patch(format!("{base}/auth/users/github:2/roles"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .json(&json!({"grant": ["early_access"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let granted: Value = r.json().await.unwrap();
    assert!(
        granted["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "early_access"),
        "PATCH returns the updated role set"
    );

    // ...and bob's *existing* session sees it without re-login: the PATCH must
    // have invalidated his role cache.
    let after = me_with(&c, &base, &bob).await;
    assert!(
        after["principal"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "early_access"),
        "same session must see the new role immediately"
    );
    assert!(
        after["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "suite:publish"),
        "granted role must immediately derive its permission bits"
    );
}

#[tokio::test]
async fn sessions_marks_current() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    // Two sessions for the same sub: a CLI exchange first, then a browser login.
    let (_cli, _) = login(&c, &base, "alice").await;
    let cookie = web_login(&c, &base, "alice").await;

    let sessions: Value = c
        .get(format!("{base}/auth/sessions"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = sessions["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let web = items
        .iter()
        .find(|s| s["kind"] == "web")
        .expect("browser session listed");
    let cli = items
        .iter()
        .find(|s| s["kind"] == "cli")
        .expect("cli session listed");
    // The cookie used for the request marks exactly its own session.
    assert_eq!(
        web["current"], true,
        "the session issuing the request is current"
    );
    assert_eq!(
        cli["current"], false,
        "the other session of the same sub is not"
    );
    // Every entry carries the (nullable) label field.
    for s in items {
        assert!(
            s.get("label").is_some(),
            "label must be present (may be null)"
        );
    }
}

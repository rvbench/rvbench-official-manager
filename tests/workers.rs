//! Worker-system end-to-end coverage (plan §5: token / routes / claim / 调度 /
//! middleware rows) against the HTTP router with the static provider.
use rvbench_manager::auth::{AuthConfig, AuthMode, ProviderConfig};
use rvbench_manager::{Config, Manager};
use rvbench_protocol::*;
use serde_json::{Value, json};
use std::time::Duration;

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
fn config(mode: AuthMode) -> Config {
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
async fn start(mode: AuthMode) -> (tempfile::TempDir, String) {
    let temp = tempfile::tempdir().unwrap();
    let m = Manager::open(Config {
        data_dir: temp.path().into(),
        ..config(mode)
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
async fn login(c: &reqwest::Client, base: &str, user: &str) -> String {
    let r = c
        .post(format!("{base}/auth/github/exchange"))
        .json(&json!({"access_token": user}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string()
}
fn bearer(t: &str) -> reqwest::header::HeaderValue {
    format!("Bearer {t}").parse().unwrap()
}
fn registration(worker_id: &str) -> Value {
    json!({
        "worker_id": worker_id, "board_id": "board", "instance_id": id(),
        "backend": "k3", "kinds": ["correctness"], "delivery": "pull",
        "url": "http://127.0.0.1:18801", "capacity": 1, "direct_active": 0,
        "ready": true, "environment": {"ops": ["add"], "dtypes": ["float32"]},
        "protocol_version": "1.0.0"
    })
}

#[tokio::test]
async fn w1_worker_records_tokens_and_channel_switch() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let alice = login(&c, &base, "alice").await;
    let root = login(&c, &base, "root").await;

    // Gray period: with no worker records anywhere, anonymous register still works.
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .json(&registration("legacy-1"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "no tokens yet → machine channel stays open"
    );

    // Create private (owner = caller) — the token appears exactly once.
    let created: Value = c
        .post(format!("{base}/workers"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .json(&json!({"worker_id": "k3-4", "visibility": "private"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["worker"]["owner"]["login"], "alice");
    assert_eq!(created["worker"]["status"], "pending");
    let token = created["token"]["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("rvbw_"));

    // Duplicate id → 409.
    let r = c
        .post(format!("{base}/workers"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .json(&json!({"worker_id": "k3-4"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);

    // public creation by a non-admin → 403; by admin → org-owned.
    let r = c
        .post(format!("{base}/workers"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .json(&json!({"worker_id": "k3-pub", "visibility": "public"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let pub_created: Value = c
        .post(format!("{base}/workers"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .json(&json!({"worker_id": "k3-pub", "visibility": "public"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pub_created["worker"]["owner"]["sub"], "org:rvbench");
    assert_eq!(pub_created["worker"]["visibility"], "public");

    // Channel is now live: anonymous register is refused, wrong-id token is 403.
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .json(&registration("legacy-2"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        401,
        "records exist → machine credentials required"
    );
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .header(reqwest::header::AUTHORIZATION, bearer(&token))
        .json(&registration("not-k3-4"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "a token registers exactly its own id");
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .header(reqwest::header::AUTHORIZATION, bearer(&token))
        .json(&registration("k3-4"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // GET /workers: alice sees hers + public; bob sees only public; admin sees all.
    let list = |who: &str| {
        let c = c.clone();
        let base = base.clone();
        let who = who.to_string();
        async move {
            c.get(format!("{base}/workers"))
                .header(reqwest::header::AUTHORIZATION, bearer(&who))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()["items"]
                .as_array()
                .unwrap()
                .len()
        }
    };
    assert_eq!(list(&alice).await, 2);
    let bob = login(&c, &base, "bob").await;
    assert_eq!(list(&bob).await, 1);
    assert_eq!(list(&root).await, 2);

    // Rotation kills the old token immediately.
    let rotated: Value = c
        .post(format!("{base}/workers/k3-4/tokens"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let new_token = rotated["token"]["token"].as_str().unwrap().to_string();
    assert_ne!(new_token, token);
    let r = c
        .post(format!("{base}/cluster/assignments/claim"))
        .header(reqwest::header::AUTHORIZATION, bearer(&token))
        .json(&json!({"worker_id":"k3-4","instance_id":id(),"request_id":id(),"wait_s":0}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "rotated-out token must die at once");
    // Bob cannot rotate or read alice's private record (404, not 403).
    let r = c
        .post(format!("{base}/workers/k3-4/tokens"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // Register the public worker at runtime so it can appear in /cluster/workers.
    let pub_token = pub_created["token"]["token"].as_str().unwrap().to_string();
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .header(reqwest::header::AUTHORIZATION, bearer(&pub_token))
        .json(&registration("k3-pub"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // /cluster/workers keeps anonymous access but redacts urls and hides private rows.
    let cluster: Value = c
        .get(format!("{base}/cluster/workers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = cluster
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["worker"]["worker_id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&"k3-pub") && !ids.contains(&"k3-4"),
        "anonymous sees public only: {ids:?}"
    );
    assert!(
        cluster
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["worker"]["url"].as_str().unwrap_or("").is_empty()),
        "url is redacted for non-admin"
    );
}

#[tokio::test]
async fn w2_claim_flow_delivers_the_token_exactly_once() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let alice = login(&c, &base, "alice").await;
    let bob = login(&c, &base, "bob").await;

    let begin: Value = c
        .post(format!("{base}/cluster/workers/claim"))
        .json(&json!({"worker_id":"k3-9","board_id":"K3-9","backend":"k3","kinds":["correctness"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = begin["code"].as_str().unwrap().to_string();
    let device = begin["device_code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 9, "XXXX-XXXX");
    assert!(
        code.chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '-')
    );
    assert!(
        begin["verification_url"]
            .as_str()
            .unwrap()
            .ends_with("/claim")
    );

    // pending → 202; approve binds the approver as owner; poll returns the token once.
    let r = c
        .get(format!("{base}/cluster/workers/claim/{device}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202);
    let approved: Value = c
        .post(format!("{base}/claims/{code}/approve"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(approved["owner"]["login"], "alice");
    assert_eq!(approved["visibility"], "private");
    let r = c
        .get(format!("{base}/cluster/workers/claim/{device}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let token = r.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(token.starts_with("rvbw_"));
    let r = c
        .get(format!("{base}/cluster/workers/claim/{device}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 410, "the token is handed out exactly once");

    // The claim page endpoint serves HTML.
    let r = c.get(format!("{base}/claim")).send().await.unwrap();
    assert!(r.status().is_success());

    // A second claim for the same worker_id: record exists → 409 at begin.
    let r = c
        .post(format!("{base}/cluster/workers/claim"))
        .json(&json!({"worker_id":"k3-9","board_id":"K3-9","backend":"k3","kinds":["correctness"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);

    // Deny path: pending → deny → 410 for the worker.
    let begin: Value = c
        .post(format!("{base}/cluster/workers/claim"))
        .json(&json!({"worker_id":"k1-2","board_id":"K1-2","backend":"k1","kinds":["func"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = begin["code"].as_str().unwrap().to_string();
    let device = begin["device_code"].as_str().unwrap().to_string();
    let r = c
        .post(format!("{base}/claims/{code}/deny"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = c
        .get(format!("{base}/cluster/workers/claim/{device}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 410);

    // /claims lists pending rows for a logged-in user only.
    let r = c.get(format!("{base}/claims")).send().await.unwrap();
    assert_eq!(r.status(), 401);
    let r = c
        .get(format!("{base}/claims"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // auth.mode=off → claim endpoints refuse with 503.
    let (_t2, base2) = start(AuthMode::Off).await;
    let r = c
        .post(format!("{base2}/cluster/workers/claim"))
        .json(&json!({"worker_id":"x","board_id":"b","backend":"k3","kinds":["func"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
}

#[tokio::test]
async fn w3_private_workers_serve_only_their_owner() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let alice = login(&c, &base, "alice").await;
    let root = login(&c, &base, "root").await;

    // One private worker owned by alice, one public worker.
    let priv_w: Value = c
        .post(format!("{base}/workers"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .json(&json!({"worker_id":"alice-k3"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pub_w: Value = c
        .post(format!("{base}/workers"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .json(&json!({"worker_id":"org-k3","visibility":"public"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let priv_token = priv_w["token"]["token"].as_str().unwrap().to_string();
    let pub_token = pub_w["token"]["token"].as_str().unwrap().to_string();

    // Register both (runtime rows).
    let mut priv_reg = registration("alice-k3");
    for (t, w) in [(&priv_token, &mut priv_reg)] {
        let r = c
            .post(format!("{base}/cluster/workers/register"))
            .header(reqwest::header::AUTHORIZATION, bearer(t))
            .json(&w)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
    let pub_reg = registration("org-k3");
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .header(reqwest::header::AUTHORIZATION, bearer(&pub_token))
        .json(&pub_reg)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let pub_instance = pub_reg["instance_id"].as_str().unwrap().to_string();
    let priv_instance = priv_reg["instance_id"].as_str().unwrap().to_string();

    // alice's job: both workers compatible; the private one may take it.
    let mut job: Value = serde_json::from_str(EXAMPLE_JOB).unwrap();
    job["op"] = json!("add");
    let alice_job: Value = c
        .post(format!("{base}/jobs"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .json(&job)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let claim =
        json!({"worker_id":"alice-k3","instance_id":priv_instance,"request_id":id(),"wait_s":0});
    let r = c
        .post(format!("{base}/cluster/assignments/claim"))
        .header(reqwest::header::AUTHORIZATION, bearer(&priv_token))
        .json(&claim)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "alice's private worker takes alice's job");

    // bob's job: the private worker must NOT get it; the public worker does.
    let bob = login(&c, &base, "bob").await;
    let bob_job: Value = c
        .post(format!("{base}/jobs"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .json(&job)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let r = c
        .post(format!("{base}/cluster/assignments/claim"))
        .header(reqwest::header::AUTHORIZATION, bearer(&priv_token))
        .json(&json!({"worker_id":"alice-k3","instance_id":priv_instance,"request_id":id(),"wait_s":0}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        204,
        "a private worker never takes a foreign job"
    );
    let r = c
        .post(format!("{base}/cluster/assignments/claim"))
        .header(reqwest::header::AUTHORIZATION, bearer(&pub_token))
        .json(
            &json!({"worker_id":"org-k3","instance_id":pub_instance,"request_id":id(),"wait_s":0}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "the public worker takes any job");

    // Ownerless legacy job (submitted while auth off is simulated by writing the
    // store directly through the anonymous gray window is gone here) — instead:
    // DELETE with an in-flight assignment is refused.
    let r = c
        .delete(format!("{base}/workers/org-k3"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409, "in-flight assignments block deletion");
    // Alice cannot drain the org worker... actually it is public, so she can.
    // A foreign PRIVATE worker drain → 404.
    let r = c
        .post(format!("{base}/cluster/workers/alice-k3/drain"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
    let r = c
        .post(format!("{base}/cluster/workers/alice-k3/drain"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "the owner drains her own worker");
    let _ = alice_job;
    let _ = bob_job;
}

#[tokio::test]
async fn worker_tokens_config_bootstraps_the_channel() {
    // config.worker_tokens[] alone (auth off) must enforce /cluster/* and keep the
    // three production boards functional with per-board tokens (design D6).
    let temp = tempfile::tempdir().unwrap();
    let token = "rvbw_bootstraptoken0000000000000000000001";
    let sha = {
        use sha2::Digest;
        let d = sha2::Sha256::digest(token.as_bytes());
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        data_dir: temp.path().into(),
        victoriametrics: None,
        auth: None,
        worker_tokens: vec![rvbench_manager::workers::BootstrapWorkerToken {
            id: "k3-1".into(),
            sha256: sha,
            created_at: None,
        }],
    };
    let m = Manager::open(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, rvbench_manager::router(m)).into_future());
    let c = client();

    // auth.mode=off, yet the channel is closed to anonymous…
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .json(&registration("k3-1"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // …and open to the bootstrap token, with the record treated as public org worker.
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .header(reqwest::header::AUTHORIZATION, bearer(token))
        .json(&registration("k3-1"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let cluster: Value = c
        .get(format!("{base}/cluster/workers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = cluster
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["worker"]["worker_id"] == "k3-1")
        .expect("bootstrap worker visible");
    assert_eq!(row["owner"]["sub"], "org:rvbench");
    // login endpoints remain disabled (mode off).
    let r = c.get(format!("{base}/auth/config")).send().await.unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["enabled"], false);
}

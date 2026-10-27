//! Console aggregate surface end-to-end coverage (plan 2026-10-27 §2 endpoints,
//! §5 compat, §6 matrix; contract v1.5): /console/bootstrap|facilities|
//! capabilities|features|instance, the dual-written /workers owner shape, and
//! the read-only viewer role. Harness copied & slimmed from tests/auth.rs
//! (static provider, admin=github:9); worker spawn follows tests/workers.rs.
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
async fn start(mode: AuthMode) -> (tempfile::TempDir, String) {
    let temp = tempfile::tempdir().unwrap();
    let m = Manager::open(Config {
        data_dir: temp.path().into(),
        ..static_config(mode)
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
    assert_eq!(r.status(), 200, "exchange {user}");
    r.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string()
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
/// Machine registration body (tests/workers.rs 手法), backend 参数化。
fn registration(worker_id: &str, backend: &str) -> Value {
    json!({
        "worker_id": worker_id, "board_id": "board", "instance_id": id(),
        "backend": backend, "kinds": ["correctness"], "delivery": "pull",
        "url": "http://127.0.0.1:18801", "capacity": 1, "direct_active": 0,
        "ready": true, "environment": {"ops": ["add"], "dtypes": ["float32"]},
        "protocol_version": "1.0.0"
    })
}
/// Create a private worker record as `owner` and register the machine with the
/// one-time token (POST /workers → POST /cluster/workers/register).
async fn spawn_worker(
    c: &reqwest::Client,
    base: &str,
    owner: &str,
    worker_id: &str,
    backend: &str,
) {
    let r = c
        .post(format!("{base}/workers"))
        .header(reqwest::header::AUTHORIZATION, bearer(owner))
        .json(&json!({"worker_id": worker_id}))
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "create {worker_id}: {}",
        r.status()
    );
    let created: Value = r.json().await.unwrap();
    let token = created["token"]["token"].as_str().unwrap().to_string();
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .header(reqwest::header::AUTHORIZATION, bearer(&token))
        .json(&registration(worker_id, backend))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "register {worker_id}");
}
fn facility_row<'a>(page: &'a Value, backend: &str) -> &'a Value {
    page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("facilities items must be an array: {page}"))
        .iter()
        .find(|f| f["backend"] == backend)
        .unwrap_or_else(|| panic!("missing {backend} row: {page}"))
}

// ---------------------------------------------------------------------------
// §6 matrix, case 1.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn bootstrap_shape_and_etag() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let bob = login(&c, &base, "bob").await;
    let alice = login(&c, &base, "alice").await;

    // Console endpoints stay behind login (they are console-only, no gray mode).
    let r = c
        .get(format!("{base}/console/bootstrap"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    let r = c
        .get(format!("{base}/console/bootstrap"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let etag = r
        .headers()
        .get("etag")
        .expect("200 must carry an ETag header")
        .to_str()
        .unwrap()
        .to_string();
    let body: Value = r.json().await.unwrap();
    for block in [
        "generated_at",
        "me",
        "nav",
        "kpi",
        "facilities",
        "recent",
        "capabilities",
        "features",
    ] {
        assert!(body.get(block).is_some(), "bootstrap missing block {block}");
    }
    // The me block is the caller's own summary, not a foreign snapshot.
    assert_eq!(body["me"]["sub"], "github:2");
    assert!(
        body["me"]["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "job:submit")
    );
    assert_eq!(body["me"]["roles_stale"], false);
    for key in ["queued", "running", "done_today", "artifacts"] {
        assert!(
            body["kpi"][key].is_u64(),
            "kpi.{key} must be an integer: {}",
            body["kpi"]
        );
    }

    // Replaying the same ETag within the ~2s window is a 304 with no body.
    let r = c
        .get(format!("{base}/console/bootstrap"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .header("if-none-match", etag.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 304);
    let bytes = r.bytes().await.unwrap();
    assert!(bytes.is_empty(), "304 must carry an empty body: {bytes:?}");

    // bob's ETag must not serve alice: me/nav are per-principal, so a
    // cross-user replay has to miss and return a fresh 200 for github:1.
    let r = c
        .get(format!("{base}/console/bootstrap"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .header("if-none-match", etag.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "ETags are per-user; a cross-user replay must not 304"
    );
    let other: Value = r.json().await.unwrap();
    assert_eq!(other["me"]["sub"], "github:1");
}

// ---------------------------------------------------------------------------
// §6 matrix, case 2.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn facilities_aggregate_by_backend() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let alice = login(&c, &base, "alice").await;

    // 3 k3 workers + 1 k1 worker, all registered ready (tests/workers.rs 手法).
    for (worker_id, backend) in [
        ("k3-a", "k3"),
        ("k3-b", "k3"),
        ("k3-c", "k3"),
        ("k1-a", "k1"),
    ] {
        spawn_worker(&c, &base, &alice, worker_id, backend).await;
    }

    let page: Value = c
        .get(format!("{base}/console/facilities"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(facility_row(&page, "k3")["online"], 3, "3 k3 registered");
    assert_eq!(facility_row(&page, "k3")["ready"], 3, "all k3 ready");
    assert_eq!(facility_row(&page, "k1")["online"], 1, "1 k1 registered");
    assert_eq!(facility_row(&page, "k1")["ready"], 1, "the k1 is ready");

    // Draining one k3 worker drops it from ready (owner drains her own worker).
    let r = c
        .post(format!("{base}/cluster/workers/k3-a/drain"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // The aggregate blocks are server-side cached for 2s (plan §7); wait the
    // window out so the re-read reflects the drain.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let page: Value = c
        .get(format!("{base}/console/facilities"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        facility_row(&page, "k3")["ready"],
        2,
        "drain must decrement k3 ready"
    );
}

// ---------------------------------------------------------------------------
// §6 matrix, case 3.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn capabilities_reflect_worker_registration() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let alice = login(&c, &base, "alice").await;

    // No worker declares triton yet: every triton cell is off with a reason.
    let caps: Value = c
        .get(format!("{base}/console/capabilities"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        matches!(caps["worker_auth"].as_str(), Some("token") | Some("open")),
        "worker_auth must be token|open: {caps}"
    );
    let triton_cells: Vec<&Value> = caps["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["runtime"] == "triton")
        .collect();
    assert!(
        !triton_cells.is_empty(),
        "the matrix must list triton rows: {caps}"
    );
    for cell in &triton_cells {
        assert_eq!(cell["available"], false, "undeclared runtime: {cell}");
        assert!(
            cell["reason"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "unavailable runtime must carry a non-empty reason: {cell}"
        );
    }

    // Register a k3 worker declaring triton via environment.implementations
    // (the same wire convention tests/contract.rs uses for scheduling).
    let r = c
        .post(format!("{base}/workers"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .json(&json!({"worker_id": "k3-triton"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let created: Value = r.json().await.unwrap();
    let token = created["token"]["token"].as_str().unwrap().to_string();
    let mut reg = registration("k3-triton", "k3");
    reg["environment"] = json!({
        "ops": ["add"],
        "dtypes": ["float32"],
        "implementations": {"triton": {"ready": true, "ops": ["add"], "dtypes": ["float32", "float16"]}}
    });
    let r = c
        .post(format!("{base}/cluster/workers/register"))
        .header(reqwest::header::AUTHORIZATION, bearer(&token))
        .json(&reg)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // The matrix is server-side cached for 2s (plan §7); the first read above
    // cached the all-false grid, so wait the window out before re-reading.
    tokio::time::sleep(Duration::from_millis(2200)).await;

    let caps: Value = c
        .get(format!("{base}/console/capabilities"))
        .header(reqwest::header::AUTHORIZATION, bearer(&alice))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cell = caps["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["runtime"] == "triton" && i["backend"] == "k3")
        .unwrap_or_else(|| panic!("triton x k3 cell missing: {caps}"))
        .clone();
    assert_eq!(
        cell["available"], true,
        "a registered declaration must flip the cell: {cell}"
    );
    assert!(cell["reason"].is_null(), "available cells carry no reason");
}

// ---------------------------------------------------------------------------
// §6 matrix, case 4.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn features_catalog_is_wellformed() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let bob = login(&c, &base, "bob").await;

    let features: Value = c
        .get(format!("{base}/console/features"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = features["items"]
        .as_array()
        .unwrap_or_else(|| panic!("features items must be an array: {features}"));
    assert_eq!(items.len(), 12, "exactly 12 feature rows: {features}");
    let mut keys = std::collections::HashSet::new();
    for f in items {
        let key = f["key"]
            .as_str()
            .unwrap_or_else(|| panic!("key must be a string: {f}"));
        assert!(keys.insert(key), "duplicate feature key: {key}");
        let status = f["status"].as_str().unwrap_or_else(|| panic!("{f}"));
        assert!(
            matches!(status, "ga" | "beta" | "planned" | "off"),
            "invalid status {status}"
        );
        let doc = f["doc"].as_str().unwrap_or_else(|| panic!("{f}"));
        assert!(
            doc.is_empty() || doc.starts_with('/'),
            "doc must be empty or a /-relative path, got {doc}"
        );
        assert!(f["name"].as_str().is_some(), "name missing: {f}");
        assert!(f["area"].as_str().is_some(), "area missing: {f}");
        assert!(f["note"].as_str().is_some(), "note missing: {f}");
    }
}

// ---------------------------------------------------------------------------
// §6 matrix, case 5.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn instance_requires_admin() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let bob = login(&c, &base, "bob").await;
    let root = login(&c, &base, "root").await; // github:9 is the config admin

    // A plain user is logged in but lacks the admin bit.
    let r = c
        .get(format!("{base}/console/instance"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    let r = c
        .get(format!("{base}/console/instance"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let inst: Value = r.json().await.unwrap();
    for key in [
        "version",
        "started_at",
        "listen",
        "data_dir",
        "ledger_bytes",
        "locked",
        "victoriametrics",
    ] {
        assert!(inst.get(key).is_some(), "instance missing {key}: {inst}");
    }
    for key in ["configured", "reachable", "latency_ms"] {
        assert!(
            inst["victoriametrics"].get(key).is_some(),
            "victoriametrics missing {key}: {inst}"
        );
    }
}

// ---------------------------------------------------------------------------
// §6 matrix, case 6.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn workers_owner_hides_deleted_user() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let alice = login(&c, &base, "alice").await;
    let root = login(&c, &base, "root").await;

    // alice owns one registered worker; the live snapshot shows her identity.
    spawn_worker(&c, &base, &alice, "alice-k3", "k3").await;
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
                .iter()
                .find(|w| w["worker_id"] == "alice-k3")
                .cloned()
                .expect("alice-k3 visible to admin")
        }
    };
    let live = list(&root).await;
    assert_eq!(live["owner"]["login"], "alice");
    assert_eq!(live["owner"]["deleted"], false);
    assert_eq!(
        live["owner"]["display"], "alice",
        "display falls back to login when name is null: {live}"
    );

    // alice deletes her account (tombstone; web session only).
    let cookie = web_login(&c, &base, "alice").await;
    let r = c
        .delete(format!("{base}/auth/me"))
        .header(reqwest::header::COOKIE, format!("rvb_session={cookie}"))
        .json(&json!({"confirm_login": "alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // The admin list now renders the tombstone: display/deleted carry the
    // truth while login stays on the wire for one compat version (the stale
    // snapshot value is exactly why display exists — plan N9).
    let tomb = list(&root).await;
    assert_eq!(tomb["owner"]["deleted"], true, "owner tombstoned: {tomb}");
    assert_eq!(
        tomb["owner"]["display"], "已注销用户",
        "owner display: {tomb}"
    );
    assert!(
        tomb["owner"]["login"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "owner.login must remain during the dual-write window: {tomb}"
    );
}

// ---------------------------------------------------------------------------
// §6 matrix, case 7 (kept here so tests/auth.rs does not grow further).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn viewer_role_is_read_only() {
    let (_t, base) = start(AuthMode::Enforce).await;
    let c = client();
    let bob = login(&c, &base, "bob").await;
    let root = login(&c, &base, "root").await;

    // Admin grants the new read-only role; the live session must see it at
    // once (the PATCH invalidates role_cache, cf. tests/auth.rs).
    let r = c
        .patch(format!("{base}/auth/users/github:2/roles"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .json(&json!({"grant": ["viewer"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "viewer must be a grantable role");
    let granted: Value = r.json().await.unwrap();
    assert!(
        granted["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "viewer"),
        "PATCH returns the updated role set: {granted}"
    );

    let me: Value = c
        .get(format!("{base}/auth/me"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        me["principal"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "viewer"),
        "roles must contain viewer: {me}"
    );
    let perms: Vec<&str> = me["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(
        !perms.contains(&"job:submit"),
        "viewer must strip every write bit: {perms:?}"
    );
    assert!(
        perms.contains(&"public:read") && perms.contains(&"job:read:self"),
        "viewer grants exactly public:read + job:read:self: {perms:?}"
    );

    // Reads still answer; submissions are refused with 403.
    let r = c
        .get(format!("{base}/jobs"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .send()
        .await
        .unwrap();
    assert_ne!(r.status(), 403, "viewer must keep read access");
    let body: Value = serde_json::from_str(EXAMPLE_JOB).unwrap();
    let r = c
        .post(format!("{base}/jobs"))
        .header(reqwest::header::AUTHORIZATION, bearer(&bob))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "viewer must not submit");

    // The worker role stays machine-only: granting it to a human is a 400.
    let r = c
        .patch(format!("{base}/auth/users/github:2/roles"))
        .header(reqwest::header::AUTHORIZATION, bearer(&root))
        .json(&json!({"grant": ["worker"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

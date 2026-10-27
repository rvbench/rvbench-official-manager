//! /console/* aggregated endpoints (plan 2026-10-27 console 整体升级, S1-S4).
//!
//! One computation entry builds every block: bootstrap embeds the exact values
//! the dedicated endpoints serve (risk table: /console/* and /observability/*
//! must not drift). All cluster numbers aggregate the committed Console
//! projection - the same View behind /observability/summary and /cluster/workers
//! - except done_today, which needs finished_at and reads the store snapshot.
//!
//! Auth note (plan §5): these routes are console-only and never join the gray
//! release - handlers resolve the principal directly (no `check()`), so
//! mode=warn still demands a login and mode=off yields 401.
//!
//! The module is declared in lib.rs as `console_api` (file src/console.rs): a
//! plain `pub mod console;` would shadow the glob-imported
//! rvbench_protocol::console used by lib.rs and observability.rs.
use crate::Manager;
use crate::auth::{self, AuthError, Principal};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rvbench_protocol::console::LeaseView;
use rvbench_protocol::console::timestamp as rfc3339_to_unix;
use rvbench_protocol::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Runtime rows are a fixed three-way enum (plan N3); tilelang has no worker
/// channel yet and stays unavailable until one registers.
const RUNTIMES: [&str; 3] = ["native-c", "triton", "tilelang"];

/// User-independent bootstrap blocks, cached 2s (plan §7 risk table). The cache
/// never contains per-user data: me/nav are computed on every request. It lives
/// on the Manager (not a process static) so distinct Manager instances — tests,
/// embedders — never serve each other's snapshot.
const GLOBAL_TTL: Duration = Duration::from_secs(2);
struct CachedBlocks {
    at: Instant,
    blocks: Arc<Value>,
}
#[derive(Default)]
pub struct GlobalCache(Mutex<Option<CachedBlocks>>);

// ---------------------------------------------------------------------------
// N1 GET /console/bootstrap
// ---------------------------------------------------------------------------

pub async fn bootstrap(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    let principal = require_login(&m, &headers).await?;
    let global = global_blocks(&m).await?;
    let tag = etag_for(&principal.sub, &global);
    if etag_matches(&headers, &tag) {
        return Ok(([(header::ETAG, tag)], StatusCode::NOT_MODIFIED).into_response());
    }
    let body = bootstrap_body(&principal, &global);
    Ok(([(header::ETAG, tag)], Json(body)).into_response())
}

/// Per-request shell (me/nav) plus the cached global blocks. Keys are exactly
/// generated_at, me, nav, kpi, facilities, recent, capabilities, features.
fn bootstrap_body(principal: &Principal, global: &Value) -> Value {
    let mut body = json!({
        "generated_at": seconds() as i64,
        "me": me_view(principal),
        "nav": nav_rows(),
    });
    if let Some(dst) = body.as_object_mut() {
        for (k, v) in global.as_object().into_iter().flatten() {
            dst.insert(k.clone(), v.clone());
        }
    }
    body
}

fn me_view(p: &Principal) -> Value {
    json!({
        "sub": p.sub,
        "login": p.login,
        "name": p.name,
        "avatar_url": p.avatar_url,
        "roles": p.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
        "permissions": p.permissions.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
        "roles_stale": p.roles_stale,
    })
}

/// Weak ETag over the caller's sub plus the serialized global part, so a hit is
/// per-user even though the cached blocks are shared (first 16 hex chars).
fn etag_for(sub: &str, global: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sub.as_bytes());
    hasher.update(serde_json::to_vec(global).unwrap_or_default());
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("W/\"{}\"", &hex[..16])
}

fn etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').map(str::trim).any(|c| c == etag || c == "*"))
}

// ---------------------------------------------------------------------------
// Shared global blocks (single computation entry for bootstrap / facilities /
// capabilities / features)
// ---------------------------------------------------------------------------

async fn global_blocks(m: &Manager) -> Result<Arc<Value>, AuthError> {
    let cache = &m.console_cache.0;
    {
        let guard = cache.lock().unwrap();
        if let Some(hit) = guard.as_ref()
            && hit.at.elapsed() < GLOBAL_TTL
        {
            return Ok(hit.blocks.clone());
        }
    }
    // Recompute outside the lock; a concurrent refresh is idempotent and the
    // last writer wins. The lock is never held across an await.
    let fresh = CachedBlocks {
        at: Instant::now(),
        blocks: Arc::new(recompute_blocks(m).await?),
    };
    let blocks = fresh.blocks.clone();
    *cache.lock().unwrap() = Some(fresh);
    Ok(blocks)
}

async fn recompute_blocks(m: &Manager) -> Result<Value, AuthError> {
    // finished_at is the only datum missing from the committed projection, so
    // done_today reads the store while everything else aggregates the same View
    // the /observability/* endpoints serve; both sources run concurrently.
    let store = m.store.clone();
    let done = store.tx(|s| {
        let now = seconds() as i64;
        // "today" starts at UTC midnight.
        let midnight = now - now.rem_euclid(86_400);
        Ok(s.jobs
            .values()
            .filter(|j| {
                j.state == JobState::Done
                    && j.finished_at
                        .as_deref()
                        .and_then(rfc3339_to_unix)
                        .is_some_and(|t| t >= midnight as f64)
            })
            .count() as i64)
    });
    let (done_today, view) = tokio::join!(done, async { m.console.snapshot() });
    let done_today = done_today.map_err(|e| AuthError::internal(&e.1))?;
    // Console::workers recomputes online (30s heartbeat TTL) and splits leases
    // into acknowledged / pending_ack (live) and uncertain (expired).
    let workers = m.console.workers(&view);
    let revoked: BTreeSet<String> = view
        .workers
        .iter()
        .filter(|w| {
            m.auth
                .workers
                .get(&w.worker.worker_id)
                .is_some_and(|r| r.status == "revoked")
        })
        .map(|w| w.worker.worker_id.clone())
        .collect();
    let now = seconds();
    let queued: i64 = view
        .counts
        .iter()
        .filter(|c| c.state.as_str() == "queued")
        .map(|c| c.count)
        .sum();
    let running: i64 = view
        .counts
        .iter()
        .filter(|c| c.state.as_str() == "running")
        .map(|c| c.count)
        .sum();
    // artifacts = 证据工件数, i.e. the unfiltered /results total.
    let recent: Vec<Value> = view
        .results
        .iter()
        .take(5)
        .map(|r| {
            json!({
                "job_id": r.job_id,
                "op": r.op,
                "backend": r.backend.as_str(),
                "state": r.state.as_str(),
                "at": rfc3339_to_unix(&r.submitted_at).map(|t| t as i64).unwrap_or(0),
            })
        })
        .collect();
    Ok(json!({
        "kpi": {
            "queued": queued,
            "running": running,
            "done_today": done_today,
            "artifacts": view.results.len(),
        },
        "facilities": facilities_rows(&workers, &view.leases, &revoked, now),
        "recent": recent,
        "capabilities": capabilities_view(
            &workers,
            &revoked,
            m.auth.workers.channel_active(),
        ),
        "features": features_rows(),
    }))
}

// ---------------------------------------------------------------------------
// N2 GET /console/facilities
// ---------------------------------------------------------------------------

pub async fn facilities(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    require_login(&m, &headers).await?;
    let global = global_blocks(&m).await?;
    Ok(Json(json!({"items": global["facilities"].clone()})))
}

#[derive(Default)]
struct FacilityAgg {
    online: i64,
    ready: i64,
    capacity: i64,
    occupied: i64,
    min_remaining: Option<f64>,
    last_seen: Option<f64>,
}

/// Aggregates the projection by backend. Only backends with at least one
/// registered worker appear (C2: the enum stays k3/k1; the frontend pads the
/// missing boards with gray cards). Online excludes revoked records and
/// heartbeats older than 30s; ready additionally requires not drained, the
/// worker-declared ready bit and a free capacity slot.
fn facilities_rows(
    workers: &[ObservedWorker],
    leases: &[LeaseView],
    revoked: &BTreeSet<String>,
    now: f64,
) -> Value {
    let mut groups: BTreeMap<String, FacilityAgg> = BTreeMap::new();
    for w in workers {
        let is_revoked = revoked.contains(&w.worker.worker_id);
        let live = w.acknowledged + w.pending_ack;
        let online = w.online && !is_revoked;
        let busy = live + w.worker.direct_active >= w.worker.capacity;
        let g = groups
            .entry(w.worker.backend.as_str().to_string())
            .or_default();
        g.online += online as i64;
        if online {
            g.capacity += w.worker.capacity;
        }
        if online && !w.drained && w.worker.ready && !busy {
            g.ready += 1;
        }
        if !is_revoked {
            if live > 0 {
                g.occupied += 1;
            }
            g.last_seen = Some(g.last_seen.map_or(w.last_seen, |t| t.max(w.last_seen)));
        }
    }
    let backend_of: BTreeMap<&str, &str> = workers
        .iter()
        .map(|w| (w.worker.worker_id.as_str(), w.worker.backend.as_str()))
        .collect();
    for l in leases {
        if l.deadline <= now || revoked.contains(&l.worker) {
            continue;
        }
        if let Some(g) = backend_of
            .get(l.worker.as_str())
            .and_then(|b| groups.get_mut(*b))
        {
            g.min_remaining = Some(
                g.min_remaining
                    .map_or(l.deadline - now, |t| t.min(l.deadline - now)),
            );
        }
    }
    json!(
        groups
            .into_iter()
            .map(|(backend, g)| {
                json!({
                    "backend": backend,
                    "online": g.online,
                    "ready": g.ready,
                    "capacity": g.capacity,
                    "occupied": g.occupied,
                    "min_lease_seconds": g.min_remaining.map(|r| r.ceil() as i64),
                    "last_seen": g.last_seen.map(auth::iso),
                })
            })
            .collect::<Vec<_>>()
    )
}

// ---------------------------------------------------------------------------
// N3 GET /console/capabilities
// ---------------------------------------------------------------------------

pub async fn capabilities(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    require_login(&m, &headers).await?;
    let global = global_blocks(&m).await?;
    Ok(Json(global["capabilities"].clone()))
}

/// Runtime x backend availability matrix. A runtime is available when an
/// online, non-revoked worker of that backend declares it ready; dtypes/kinds
/// aggregate from those supporters only.
fn capabilities_view(
    workers: &[ObservedWorker],
    revoked: &BTreeSet<String>,
    token_channel: bool,
) -> Value {
    // C2: the matrix always lists the full k1/k3 grid so the console renders
    // every runtime row even with zero registrations (all false + reason).
    let backends = ["k1", "k3"];
    let mut items = Vec::new();
    for backend in backends {
        let online: Vec<&ObservedWorker> = workers
            .iter()
            .filter(|w| {
                w.worker.backend.as_str() == backend
                    && w.online
                    && !revoked.contains(&w.worker.worker_id)
            })
            .collect();
        for runtime in RUNTIMES {
            let mut dtypes = BTreeSet::new();
            let mut kinds = BTreeSet::new();
            let mut available = false;
            for w in &online {
                if let Some(ds) = runtime_dtypes(w, runtime) {
                    available = true;
                    dtypes.extend(ds);
                    kinds.extend(w.worker.kinds.iter().map(|k| k.as_str()));
                }
            }
            let reason = if available {
                None
            } else if online.is_empty() {
                Some("该后端暂无在线 worker")
            } else {
                Some("无在线 worker 声明该运行时")
            };
            items.push(json!({
                "runtime": runtime,
                "backend": backend,
                "available": available,
                "reason": reason,
                "dtypes": dtypes.into_iter().collect::<Vec<_>>(),
                "kinds": kinds.into_iter().collect::<Vec<_>>(),
            }));
        }
    }
    json!({
        // C3: the worker channel enforces rvbw_ tokens as soon as one exists.
        "worker_auth": if token_channel { "token" } else { "open" },
        "items": items,
    })
}

/// Runtime declaration mapping, kept in lockstep with worker_supports_request:
/// environment.implementations[name].ready == true declares a runtime with its
/// ops/dtypes; a registration without that map only serves its backend's
/// implicit runtime (native-c on k1, triton on k3).
fn runtime_dtypes(w: &ObservedWorker, runtime: &str) -> Option<Vec<String>> {
    let env = &w.worker.environment.additional_properties;
    if let Some(modes) = env.get("implementations").and_then(Value::as_object) {
        let capability = modes.get(runtime)?;
        if capability.get("ready") != Some(&json!(true)) {
            return None;
        }
        return Some(
            capability
                .get("dtypes")
                .map(string_values)
                .unwrap_or_default(),
        );
    }
    if runtime != default_implementation(&w.worker.backend).as_str() {
        return None;
    }
    Some(env.get("dtypes").map(string_values).unwrap_or_default())
}

fn string_values(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// N4 GET /console/features
// ---------------------------------------------------------------------------

pub async fn features(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    require_login(&m, &headers).await?;
    Ok(Json(json!({"items": features_rows()})))
}

struct FeatureRow {
    key: &'static str,
    name: &'static str,
    area: &'static str,
    status: &'static str,
    note: &'static str,
    doc: &'static str,
}

/// Embedded 12-row availability matrix (plan N4): static content, no library.
const FEATURES: &[FeatureRow] = &[
    FeatureRow {
        key: "job-submit",
        name: "任务提交",
        area: "工作台",
        status: "ga",
        note: "软件/硬件两类提交，client_request_id 幂等重试",
        doc: "/docs/features/job-submit.md",
    },
    FeatureRow {
        key: "records-filter",
        name: "任务记录筛选",
        area: "工作台",
        status: "ga",
        note: "搜索/后端/类型/状态多条件筛选与分页",
        doc: "/docs/features/records-filter.md",
    },
    FeatureRow {
        key: "leaderboard",
        name: "排行榜",
        area: "工作台",
        status: "ga",
        note: "同板同环境分组，按实现取最新有效测量",
        doc: "/docs/features/leaderboard.md",
    },
    FeatureRow {
        key: "presets",
        name: "预设方案",
        area: "工作台",
        status: "beta",
        note: "v1 存 localStorage，支持 JSON 导入导出",
        doc: "/docs/features/presets.md",
    },
    FeatureRow {
        key: "profile",
        name: "个人中心",
        area: "工作台",
        status: "ga",
        note: "档案、凭证、会话与账号注销",
        doc: "/docs/features/profile.md",
    },
    FeatureRow {
        key: "api-tokens",
        name: "API 凭证",
        area: "工作台",
        status: "ga",
        note: "CLI rvb_ token 自助创建与吊销",
        doc: "/docs/features/api-tokens.md",
    },
    FeatureRow {
        key: "audit",
        name: "审计查询",
        area: "控制台",
        status: "ga",
        note: "管理员可查登录与敏感操作审计流水",
        doc: "/docs/features/audit.md",
    },
    FeatureRow {
        key: "console-users",
        name: "用户与角色管理",
        area: "控制台",
        status: "beta",
        note: "成员列表与角色授予；viewer 只读角色随 S6 落地",
        doc: "/docs/features/console-users.md",
    },
    FeatureRow {
        key: "facilities",
        name: "设施管理",
        area: "控制台",
        status: "beta",
        note: "worker 排空/恢复与控制面自述",
        doc: "/docs/features/facilities.md",
    },
    FeatureRow {
        key: "runtime-matrix",
        name: "运行时矩阵",
        area: "设施",
        status: "beta",
        note: "native-c/triton 实时可用性聚合，tilelang 待 worker 接入",
        doc: "/docs/features/runtime-matrix.md",
    },
    FeatureRow {
        key: "suites",
        name: "评测套件",
        area: "设施",
        status: "beta",
        note: "套件卡与契约提示；发布/运行需 early_access",
        doc: "/docs/features/suites.md",
    },
    FeatureRow {
        key: "multi-board",
        name: "多板卡支持",
        area: "设施",
        status: "planned",
        note: "XiangShan/Ruyi/XuanTie 等待 worker 注册后扩 BackendId",
        doc: "",
    },
];

fn features_rows() -> Value {
    json!(
        FEATURES
            .iter()
            .map(|f| {
                json!({
                    "key": f.key,
                    "name": f.name,
                    "area": f.area,
                    "status": f.status,
                    "note": f.note,
                    "doc": f.doc,
                })
            })
            .collect::<Vec<_>>()
    )
}

// ---------------------------------------------------------------------------
// Navigation catalog (12 views, front plan 2026-10-27 §0/§1)
// ---------------------------------------------------------------------------

struct NavEntry {
    key: &'static str,
    group: &'static str,
    label: &'static str,
    permission: Option<&'static str>,
}

/// 工作台 6 (submit split into software/hardware), 控制台 3 (admin pages carry
/// an admin-only permission bit; the frontend also gates #/admin/* on the
/// admin role), 设施 3. A null permission is visible to every logged-in user.
const NAV: &[NavEntry] = &[
    NavEntry {
        key: "status",
        group: "工作台",
        label: "总控台",
        permission: None,
    },
    NavEntry {
        key: "submit",
        group: "工作台",
        label: "任务提交 · 软件",
        permission: Some("job:submit"),
    },
    NavEntry {
        key: "submit-hardware",
        group: "工作台",
        label: "任务提交 · 硬件",
        permission: Some("job:submit"),
    },
    NavEntry {
        key: "results",
        group: "工作台",
        label: "任务记录",
        permission: None,
    },
    NavEntry {
        key: "leaderboard",
        group: "工作台",
        label: "排行榜",
        permission: None,
    },
    NavEntry {
        key: "profile",
        group: "工作台",
        label: "个人中心",
        permission: None,
    },
    NavEntry {
        key: "admin-users",
        group: "控制台",
        label: "用户管理",
        permission: Some("job:read:all"),
    },
    NavEntry {
        key: "admin-roles",
        group: "控制台",
        label: "权限管理",
        permission: Some("job:read:all"),
    },
    NavEntry {
        key: "admin-facilities",
        group: "控制台",
        label: "设施管理",
        permission: Some("worker:manage:all"),
    },
    NavEntry {
        key: "workers",
        group: "设施",
        label: "后端 Workers",
        permission: None,
    },
    NavEntry {
        key: "suites",
        group: "设施",
        label: "评测套件",
        permission: Some("suite:read:self"),
    },
    NavEntry {
        key: "features",
        group: "设施",
        label: "功能可用性",
        permission: None,
    },
];

fn nav_rows() -> Value {
    json!(
        NAV.iter()
            .map(|n| {
                json!({
                    "key": n.key,
                    "group": n.group,
                    "label": n.label,
                    "permission": n.permission,
                })
            })
            .collect::<Vec<_>>()
    )
}

// ---------------------------------------------------------------------------
// N8 GET /console/instance (admin only)
// ---------------------------------------------------------------------------

pub async fn instance(
    State(m): State<Arc<Manager>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    let principal = require_login(&m, &headers).await?;
    if !principal.is_admin {
        return Err(AuthError::forbidden("admin role required"));
    }
    // ledger = the ManagerData snapshot file (manager.sqlite) written by Store.
    let ledger_bytes = std::fs::metadata(m.config.data_dir.join("manager.sqlite"))
        .map(|md| md.len() as i64)
        .unwrap_or(0);
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        // Console::started is captured once at Manager::open and backs the
        // process_start_time_seconds metric.
        "started_at": m.console.started as i64,
        "listen": m.config.listen,
        "data_dir": m.config.data_dir.display().to_string(),
        "ledger_bytes": ledger_bytes,
        // The snapshot store serializes writes internally (Store::tx); there is
        // no externally visible snapshot write-lock state, so this stays false.
        "locked": false,
        "victoriametrics": vm_probe(&m).await,
    })))
}

/// Lightweight VictoriaMetrics /health probe (2s budget). Any HTTP answer
/// counts as reachable; a failure degrades the field, never the endpoint.
async fn vm_probe(m: &Manager) -> Value {
    let Some(base) = m.config.victoriametrics.as_deref() else {
        return json!({"configured": false, "reachable": null, "latency_ms": null});
    };
    let started = Instant::now();
    let reached = m
        .client
        .get(format!("{}/health", base.trim_end_matches('/')))
        .timeout(Duration::from_secs(2))
        .send()
        .await;
    match reached {
        Ok(_) => json!({
            "configured": true,
            "reachable": true,
            "latency_ms": started.elapsed().as_millis() as u64,
        }),
        Err(_) => json!({"configured": true, "reachable": false, "latency_ms": null}),
    }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// Any logged-in principal (user or machine channel); no gray release.
async fn require_login(m: &Manager, headers: &HeaderMap) -> Result<Principal, AuthError> {
    m.auth
        .resolve(headers)
        .await
        .ok_or_else(|| AuthError::unauthenticated("authentication required"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker(
        id: &str,
        backend: &str,
        capacity: i64,
        ready: bool,
        drained: bool,
        online: bool,
        environment: Value,
    ) -> ObservedWorker {
        let reg: WorkerRegistration = serde_json::from_value(json!({
            "worker_id": id,
            "board_id": "board",
            "instance_id": "i",
            "backend": backend,
            "kinds": ["func", "performance"],
            "delivery": "pull",
            "url": "http://127.0.0.1:1",
            "capacity": capacity,
            "direct_active": 0,
            "ready": ready,
            "environment": environment,
            "protocol_version": "1.0.0"
        }))
        .unwrap();
        ObservedWorker {
            worker: reg,
            last_seen: 999_997.,
            online,
            drained,
            pending_ack: 0,
            acknowledged: 0,
            uncertain: 0,
        }
    }

    #[test]
    fn facilities_counts_by_backend_and_excludes_drained_and_revoked() {
        let now = 1_000_000.;
        let mut a = worker(
            "w-a",
            "k3",
            2,
            true,
            false,
            true,
            json!({"ops":["add"],"dtypes":["float32"]}),
        );
        let mut b = worker(
            "w-b",
            "k3",
            1,
            true,
            true,
            true,
            json!({"ops":["add"],"dtypes":["float32"]}),
        );
        // One live acknowledged lease each; the expired unacked lease on w-a is
        // "uncertain" and never counts as occupied (Console::workers semantics).
        a.acknowledged = 1;
        b.acknowledged = 1;
        let c = worker(
            "w-c",
            "k1",
            2,
            true,
            false,
            true,
            json!({"implementations":{"native-c":{"ready":true,"ops":["add"],"dtypes":["float32"]}}}),
        );
        let d = worker(
            "w-d",
            "k1",
            4,
            true,
            false,
            true,
            json!({"ops":["add"],"dtypes":["float32"]}),
        );
        let leases = vec![
            LeaseView {
                worker: "w-a".into(),
                acknowledged: true,
                deadline: now + 22.5,
            },
            LeaseView {
                worker: "w-a".into(),
                acknowledged: false,
                deadline: now - 5.,
            },
            LeaseView {
                worker: "w-b".into(),
                acknowledged: true,
                deadline: now + 40.,
            },
        ];
        let rows = facilities_rows(
            &[a, b, c, d],
            &leases,
            &BTreeSet::from(["w-d".to_string()]),
            now,
        );
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 2, "one row per backend with registered workers");
        let k3 = rows.iter().find(|r| r["backend"] == "k3").unwrap();
        assert_eq!(k3["online"], 2);
        assert_eq!(k3["ready"], 1, "w-a ready, drained w-b is not");
        assert_eq!(k3["capacity"], 3);
        assert_eq!(k3["occupied"], 2, "w-a and w-b hold live leases");
        assert_eq!(
            k3["min_lease_seconds"], 23,
            "ceil(22.5), the dead lease is ignored"
        );
        assert_eq!(k3["last_seen"], auth::iso(999_997.));
        let k1 = rows.iter().find(|r| r["backend"] == "k1").unwrap();
        assert_eq!(k1["online"], 1, "revoked w-d does not count as online");
        assert_eq!(k1["capacity"], 2, "capacity sums online workers only");
        assert_eq!(k1["occupied"], 0);
        assert!(k1["min_lease_seconds"].is_null());
    }

    #[test]
    fn capabilities_reflect_runtime_declarations() {
        let legacy_k3 = worker(
            "w-k3",
            "k3",
            1,
            true,
            false,
            true,
            json!({"ops":["add"],"dtypes":["float32"]}),
        );
        let k1 = worker(
            "w-k1",
            "k1",
            1,
            true,
            false,
            true,
            json!({"implementations":{
                "native-c": {"ready": true, "dtypes": ["float32", "float16"]},
                "triton": {"ready": false}
            }}),
        );
        let view = capabilities_view(&[legacy_k3, k1], &BTreeSet::new(), true);
        assert_eq!(view["worker_auth"], "token");
        let items = view["items"].as_array().unwrap();
        assert_eq!(items.len(), 6, "3 runtimes x 2 backends");
        let find = |runtime: &str, backend: &str| {
            items
                .iter()
                .find(|i| i["runtime"] == runtime && i["backend"] == backend)
                .unwrap()
                .clone()
        };
        // Legacy k3 registration: implicit runtime is triton, never native-c.
        let t = find("triton", "k3");
        assert_eq!(t["available"], true);
        assert_eq!(t["dtypes"], json!(["float32"]));
        assert_eq!(t["kinds"], json!(["func", "performance"]));
        assert!(t["reason"].is_null());
        assert_eq!(find("native-c", "k3")["available"], false);
        // k1: declared native-c, triton explicitly not ready, tilelang absent.
        let n = find("native-c", "k1");
        assert_eq!(n["available"], true);
        assert_eq!(n["dtypes"], json!(["float16", "float32"]));
        assert_eq!(find("triton", "k1")["reason"], "无在线 worker 声明该运行时");
        assert_eq!(find("tilelang", "k1")["available"], false);
        assert_eq!(
            capabilities_view(&[], &BTreeSet::new(), false)["worker_auth"],
            "open"
        );
    }

    #[test]
    fn capabilities_report_backend_without_online_workers() {
        let offline = worker(
            "w-off",
            "k1",
            1,
            true,
            false,
            false,
            json!({"ops":["add"],"dtypes":["float32"]}),
        );
        let view = capabilities_view(&[offline], &BTreeSet::new(), false);
        let item = &view["items"][0];
        assert_eq!(item["runtime"], "native-c");
        assert_eq!(item["available"], false);
        assert_eq!(item["reason"], "该后端暂无在线 worker");
        assert_eq!(item["dtypes"], json!([]));
    }

    #[test]
    fn nav_catalog_is_wellformed() {
        assert_eq!(NAV.len(), 12);
        let mut keys = BTreeSet::new();
        for n in NAV {
            assert!(!n.key.is_empty() && !n.group.is_empty() && !n.label.is_empty());
            assert!(keys.insert(n.key), "duplicate nav key {}", n.key);
            if let Some(p) = n.permission {
                assert!(p.contains(':'), "permission bit expected, got {p}");
            }
        }
        let groups: BTreeSet<_> = NAV.iter().map(|n| n.group).collect();
        assert_eq!(groups, BTreeSet::from(["工作台", "控制台", "设施"]));
    }

    #[test]
    fn features_catalog_is_wellformed() {
        assert_eq!(FEATURES.len(), 12);
        let mut keys = BTreeSet::new();
        for f in FEATURES {
            assert!(keys.insert(f.key), "duplicate feature key {}", f.key);
            assert!(["ga", "beta", "planned", "off"].contains(&f.status));
            assert!(!f.note.is_empty());
            assert!(
                f.doc.is_empty() || (f.doc.starts_with('/') && !f.doc[1..].starts_with('/')),
                "doc must be a relative path or empty, got {}",
                f.doc
            );
        }
    }

    #[test]
    fn etag_is_stable_and_user_scoped() {
        let g = json!({"kpi": {"queued": 1}, "facilities": [], "recent": [], "capabilities": {}, "features": []});
        let a1 = etag_for("github:1", &g);
        assert_eq!(a1, etag_for("github:1", &g));
        assert_ne!(a1, etag_for("github:2", &g), "304 must be user-scoped");
        assert_ne!(a1, etag_for("github:1", &json!({"kpi": {"queued": 2}})));
        assert_eq!(a1.len(), 20, "W/\"\" + 16 hex chars");
        assert!(a1.starts_with("W/\"") && a1.ends_with('"'));
        assert!(a1[3..19].bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn bootstrap_body_has_exactly_the_contract_keys() {
        let p = Principal {
            sub: "github:1".into(),
            login: "alice".into(),
            name: Some("Alice".into()),
            email: None,
            avatar_url: None,
            provider: "static".into(),
            roles: vec![],
            permissions: vec![],
            roles_stale: false,
            is_admin: false,
            session_kind: "web".into(),
            session_expires_at: 0.,
            session_sha256: String::new(),
            first_seen: 0.,
            last_seen: 0.,
        };
        let global = json!({
            "kpi": {"queued": 0, "running": 0, "done_today": 0, "artifacts": 0},
            "facilities": [],
            "recent": [],
            "capabilities": {"worker_auth": "open", "items": []},
            "features": [],
        });
        let body = bootstrap_body(&p, &global);
        let mut keys: Vec<String> = body.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "capabilities",
                "facilities",
                "features",
                "generated_at",
                "kpi",
                "me",
                "nav",
                "recent",
            ]
        );
        assert_eq!(body["me"]["sub"], "github:1");
        assert_eq!(body["capabilities"]["worker_auth"], "open");
        assert_eq!(body["nav"].as_array().unwrap().len(), 12);
    }
}

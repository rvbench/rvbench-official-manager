//! Durable unified submission and scheduling. Push and pull call the same transaction.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use rvbench_protocol::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub mod auth;
// Declared as console_api (file src/console.rs): a plain `pub mod console;`
// would shadow the glob-imported rvbench_protocol::console module that lib.rs
// and observability.rs reference as `console::…`.
#[path = "console.rs"]
pub mod console_api;
pub mod observability;
pub mod workers;
use auth::Principal;
use rvbench_protocol::console::{Console, LeaseView};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub data_dir: PathBuf,
    #[serde(default)]
    pub victoriametrics: Option<String>,
    #[serde(default)]
    pub auth: Option<auth::AuthConfig>,
    #[serde(default)]
    pub worker_tokens: Vec<workers::BootstrapWorkerToken>,
}
#[derive(Default, Serialize, Deserialize)]
pub struct ManagerData {
    epoch: String,
    jobs: BTreeMap<String, JobRecord>,
    workers: BTreeMap<String, Node>,
    assignments: BTreeMap<String, Grant>,
    claims: BTreeMap<String, (String, Option<String>)>,
    #[serde(default)]
    claim_times: BTreeMap<String, f64>,
    events: BTreeMap<String, String>,
    /// job_id -> owner sub, written in the same transaction as the job (design §2).
    #[serde(default)]
    owners: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Node {
    info: WorkerRegistration,
    last_seen: f64,
    drained: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct Grant {
    assignment: Assignment,
    acknowledged: bool,
    lease_until: f64,
}
pub struct Manager {
    pub console: Arc<Console>,
    pub console_cache: console_api::GlobalCache,
    pub collection: std::sync::RwLock<CollectionHealth>,
    pub query_limit: tokio::sync::Semaphore,
    pub config: Config,
    pub auth: Arc<auth::AuthState>,
    store: Store<ManagerData>,
    client: reqwest::Client,
    _lock: std::fs::File,
}
impl Manager {
    pub async fn open(config: Config) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(&config.data_dir)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(config.data_dir.join("manager.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        let console = Console::new("manager", None);
        let project = console.clone();
        let store = Store::<ManagerData>::open(&config.data_dir.join("manager.sqlite"))?.with_observer(move |s| {
            let ws=s.workers.values().map(|n|serde_json::from_value(json!({"worker":n.info,"last_seen":n.last_seen,"online":true,"drained":n.drained,"pending_ack":0,"acknowledged":0,"uncertain":0})).unwrap()).collect();
            let leases=s.assignments.values().filter(|g|!terminal(&s.jobs[&g.assignment.job_id].state)).map(|g|LeaseView{worker:g.assignment.worker_id.clone(),acknowledged:g.acknowledged,deadline:if g.acknowledged{g.lease_until}else{g.assignment.expires_at}}).collect();
            project.update(s.jobs.values().map(|j|(j,"managed")).collect(),ws,leases,0,0.);
        })?;
        store
            .tx(|s| {
                if s.epoch.is_empty() {
                    s.epoch = id();
                }
                Ok(())
            })
            .await
            .map_err(|e| anyhow::anyhow!(e.1))?;
        for t in &config.worker_tokens {
            anyhow::ensure!(
                t.sha256.len() == 64
                    && t.sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()),
                "worker_tokens[{}].sha256 must be 64 lowercase hex chars",
                t.id
            );
        }
        let bootstrap = config
            .worker_tokens
            .iter()
            .map(|t| workers::migrate::BootstrapToken {
                id: t.id.clone(),
                sha256: t.sha256.clone(),
            })
            .collect();
        // One AuthState either way: the worker channel is independent of
        // auth.mode (design §2), so the registry must load even when the user
        // system is off. Default config = mode off = login endpoints disabled.
        let auth = auth::AuthState::open(
            config.auth.clone().unwrap_or_default(),
            &config.data_dir,
            bootstrap,
        )
        .await?;
        Ok(Arc::new(Self {
            console,
            console_cache: console_api::GlobalCache::default(),
            collection: std::sync::RwLock::new(serde_json::from_value(json!({"status":"unavailable","errors":["Waiting for VictoriaMetrics health check"]})).unwrap()),
            query_limit: tokio::sync::Semaphore::new(4),
            config,
            auth,
            store,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()?,
            _lock: lock,
        }))
    }
    pub fn start(self: &Arc<Self>) {
        let health = self.clone();
        tokio::spawn(async move {
            loop {
                health.update_collection().await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        let auth = self.auth.clone();
        tokio::spawn(async move {
            loop {
                auth.db.cleanup_sync(seconds());
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
        // Aggregated worker heartbeats: memory on every register, disk every 10s
        // (design §4.3), plus claim expiry/cleanup sweeps.
        let auth = self.auth.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let dirty: Vec<_> = auth
                    .heartbeats
                    .lock()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .collect();
                if !dirty.is_empty() {
                    let _ = auth
                        .db
                        .call(move |c| {
                            workers::store::flush_last_seen(c, &dirty)
                                .map_err(|e| auth::AuthError::internal(e.to_string()))
                        })
                        .await;
                }
                let now = seconds();
                let _ = auth
                    .db
                    .call(move |c| {
                        workers::store::expire_claims(c, now)
                            .and_then(|_| workers::store::cleanup_claims(c, now))
                            .map_err(|e| auth::AuthError::internal(e.to_string()))
                    })
                    .await;
            }
        });
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = manager.push_tick().await {
                    eprintln!("push: {}", e.1);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
    async fn push_tick(&self) -> Result<(), ApiError> {
        let workers = self
            .store
            .tx(|s| {
                Ok(s.workers
                    .values()
                    .filter(|n| n.info.delivery == DeliveryMode::Push)
                    .map(|n| n.info.clone())
                    .collect::<Vec<_>>())
            })
            .await?;
        for w in workers {
            let wid = w.worker_id.clone();
            let instance = w.instance_id.clone();
            let ownership = self.auth.workers.ownership();
            let assignment = self
                .store
                .tx(move |s| {
                    let pending = s
                        .assignments
                        .values()
                        .find(|g| {
                            g.assignment.worker_id == wid
                                && g.assignment.instance_id == instance
                                && !g.acknowledged
                                && !terminal(&s.jobs[&g.assignment.job_id].state)
                                // An expired grant is undeliverable; re-allocate instead of
                                // retrying it forever.
                                && g.assignment.expires_at > seconds()
                        })
                        .map(|g| g.assignment.clone());
                    if pending.is_some() {
                        return Ok(pending);
                    }
                    allocate(s, &wid, &instance, &ownership)
                })
                .await?;
            if let Some(a) = assignment {
                // A lost response never frees ownership or creates a new attempt. Retry the
                // exact assignment. The worker's persistent attempt index deduplicates it.
                if a.expires_at >= seconds() {
                    let response = self
                        .client
                        .post(format!("{}/jobs", w.url.trim_end_matches('/')))
                        .json(&WorkerSubmission {
                            request: a.request.clone(),
                            assignment: Some(a),
                        })
                        .send()
                        .await;
                    if let Err(e) = response {
                        eprintln!("push {}: {e}", w.worker_id);
                    }
                }
            }
        }
        Ok(())
    }
    pub async fn submit(
        &self,
        request: JobRequest,
        sub: Option<String>,
    ) -> Result<JobRecord, ApiError> {
        validate_request(&request).map_err(ApiError::bad)?;
        self.store
            .tx(move |s| {
                if let Some(key) = &request.client_request_id
                    && let Some(old) = s
                        .jobs
                        .values()
                        .find(|j| j.request.client_request_id.as_ref() == Some(key))
                {
                    if digest(&old.request) != digest(&request) {
                        return Err(ApiError::conflict("client_request_id digest mismatch"));
                    }
                    return Ok(old.clone());
                }
                if s.jobs.values().filter(|j| !terminal(&j.state)).count() >= 1000 {
                    return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "queue full".into()));
                }
                let r = record(request);
                if let Some(sub) = &sub {
                    s.owners.insert(r.job_id.clone(), sub.clone());
                }
                s.jobs.insert(r.job_id.clone(), r.clone());
                Ok(r)
            })
            .await
    }
    pub async fn claim_page() -> impl IntoResponse {
        Html(workers::CLAIM_HTML)
    }
    pub async fn register(&self, info: WorkerRegistration) -> Result<Value, ApiError> {
        validate(
            "WorkerRegistration",
            &serde_json::to_value(&info).map_err(anyhow::Error::from)?,
        )
        .map_err(ApiError::bad)?;
        if info.delivery != DeliveryMode::Pull {
            let url = reqwest::Url::parse(&info.url).map_err(ApiError::bad)?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(ApiError::bad("push URL must be http(s)"));
            }
        }
        self.store
            .tx(move |s| {
                let drained = s.workers.get(&info.worker_id).is_some_and(|n| n.drained);
                if let Some(old) = s.workers.get(&info.worker_id) {
                    if old.info.instance_id != info.instance_id && seconds() - old.last_seen < 30.0
                    {
                        return Err(ApiError::conflict(
                            "worker_id has a live different instance",
                        ));
                    }
                    if old.info.instance_id == info.instance_id
                        && (old.info.board_id != info.board_id
                            || old.info.backend != info.backend
                            || old.info.kinds != info.kinds
                            || old.info.delivery != info.delivery
                            || old.info.capacity != info.capacity
                            || old.info.url != info.url)
                    {
                        return Err(ApiError::conflict("instance capability identity changed"));
                    }
                }
                s.workers.insert(
                    info.worker_id.clone(),
                    Node {
                        info,
                        last_seen: seconds(),
                        drained,
                    },
                );
                Ok(json!({"registered":true,"manager_epoch":s.epoch,"heartbeat_s":2,"ttl_s":30}))
            })
            .await
    }
    pub async fn claim(&self, c: ClaimRequest) -> Result<Option<Assignment>, ApiError> {
        let deadline = Instant::now() + Duration::from_secs(c.wait_s as u64);
        let ownership = self.auth.workers.ownership();
        loop {
            let request = c.clone();
            let result = self
                .store
                .tx({
                    let ownership = ownership.clone();
                    move |s| {
                        s.claims.retain(|id, (_, grant)| {
                            grant.is_some()
                                || s.claim_times.get(id).is_some_and(|t| seconds() - t < 300.0)
                        });
                        s.claim_times.retain(|id, _| s.claims.contains_key(id));
                        let fingerprint = digest(&request);
                        if let Some((hash, grant)) = s.claims.get(&request.request_id) {
                            if *hash != fingerprint {
                                return Err(ApiError::conflict("claim request_id digest mismatch"));
                            }
                            return Ok(grant
                                .as_ref()
                                .map(|id| s.assignments[id].assignment.clone()));
                        }
                        let node = s
                            .workers
                            .get(&request.worker_id)
                            .ok_or_else(ApiError::missing)?;
                        if node.info.instance_id != request.instance_id {
                            return Err(ApiError::conflict("claim instance mismatch"));
                        }
                        if node.info.delivery == DeliveryMode::Push {
                            return Err(ApiError::conflict("worker is push-only"));
                        }
                        let a = allocate(s, &request.worker_id, &request.instance_id, &ownership)?;
                        // Empty receipts are recorded only once the long poll actually finishes.
                        if let Some(a) = &a {
                            s.claims.insert(
                                request.request_id,
                                (fingerprint, Some(a.assignment_id.clone())),
                            );
                        }
                        Ok(a)
                    }
                })
                .await?;
            if result.is_some() {
                return Ok(result);
            }
            if Instant::now() >= deadline {
                let key = c.request_id.clone();
                let hash = digest(&c);
                return self
                    .store
                    .tx(move |s| {
                        if let Some((old, a)) = s.claims.get(&key) {
                            if *old != hash {
                                return Err(ApiError::conflict("claim request_id digest mismatch"));
                            }
                            return Ok(a.as_ref().map(|id| s.assignments[id].assignment.clone()));
                        }
                        s.claim_times.insert(key.clone(), seconds());
                        s.claims.insert(key, (hash, None));
                        Ok(None)
                    })
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub async fn acknowledge(&self, key: String, ack: Ack, renew: bool) -> Result<Value, ApiError> {
        self.store
            .tx(move |s| {
                let grant = if renew {
                    s.assignments
                        .values_mut()
                        .find(|g| g.assignment.lease_id == key)
                } else {
                    s.assignments.get_mut(&key)
                }
                .ok_or_else(ApiError::missing)?;
                let a = &grant.assignment;
                if a.worker_id != ack.worker_id
                    || a.instance_id != ack.instance_id
                    || a.lease_id != ack.lease_id
                    || a.job_id != ack.worker_job_id
                {
                    return Err(ApiError::conflict("lease/job ownership mismatch"));
                }
                if renew && !grant.acknowledged {
                    return Err(ApiError::conflict("assignment not acknowledged"));
                }
                grant.acknowledged = true;
                grant.lease_until = seconds() + 30.0;
                let r = s.jobs.get_mut(&a.job_id).unwrap();
                if !terminal(&r.state) {
                    r.state = JobState::Running;
                    if r.started_at.is_none() {
                        r.started_at = Some(now());
                    }
                }
                Ok(json!({"accepted":true,"lease_until":grant.lease_until}))
            })
            .await
    }
    pub async fn receive(&self, key: String, e: JobEvent) -> Result<Value, ApiError> {
        self.store
            .tx(move |s| {
                let grant = s.assignments.get(&key).ok_or_else(ApiError::missing)?;
                let a = &grant.assignment;
                let r = &e.record;
                if digest(a) != digest(&e.assignment)
                    || key != e.assignment.assignment_id
                    || r.job_id != a.job_id
                    || r.worker_id != a.worker_id
                    || r.instance_id != a.instance_id
                    || r.attempt_id.as_ref() != Some(&a.attempt_id)
                    || r.assignment_id.as_ref() != Some(&a.assignment_id)
                    || r.lease_id.as_ref() != Some(&a.lease_id)
                    || digest(&r.request) != a.request_sha256
                {
                    return Err(ApiError::conflict("event ownership/digest mismatch"));
                }
                if r.board_id != s.jobs[&a.job_id].board_id
                    || !terminal(&r.state)
                    || e.event_seq != 1
                    || e.event_id != format!("{}:terminal", a.attempt_id)
                {
                    return Err(ApiError::conflict("invalid terminal event"));
                }
                if r.state == JobState::Done
                    && (!r.compilation.as_ref().is_some_and(|p| {
                        p.status == PhaseStatus::Passed && !p.artifacts.is_empty()
                    }) || (r.request.kind != JobKind::Func
                        && !r.evaluation.as_ref().is_some_and(|p| {
                            p.status == PhaseStatus::Passed && !p.artifacts.is_empty()
                        })))
                {
                    return Err(ApiError::bad(
                        "done requires compiler and evaluator evidence",
                    ));
                }
                let hash = digest(&e);
                if let Some(old) = s.events.get(&e.event_id) {
                    if old != &hash {
                        return Err(ApiError::conflict("event replay changed content"));
                    }
                    return Ok(json!({"accepted":true,"duplicate":true}));
                }
                let mut completed = e.record;
                completed.submitted_at = s.jobs[&a.job_id].submitted_at.clone();
                s.jobs.insert(a.job_id.clone(), completed);
                s.events.insert(e.event_id, hash);
                Ok(json!({"accepted":true,"duplicate":false}))
            })
            .await
    }
}
fn allocate(
    s: &mut ManagerData,
    worker: &str,
    instance: &str,
    ownership: &BTreeMap<String, (String, bool)>,
) -> Result<Option<Assignment>, ApiError> {
    let node = s.workers.get(worker).ok_or_else(ApiError::missing)?;
    if node.info.instance_id != instance {
        return Err(ApiError::conflict("instance mismatch"));
    }
    if node.drained || !node.info.ready || seconds() - node.last_seen > 30.0 {
        return Ok(None);
    }
    // A grant holds a slot only while its deadline is live. An un-acknowledged
    // grant expires out of delivery (push never reached the worker, or the worker
    // never took it), and an acknowledged grant expires once the worker stops
    // renewing. Counting dead grants pinned capacity=1 workers forever — even
    // across a restart with a fresh instance_id — so the slot never came back.
    let now = seconds();
    // Recycle dead grants first: the job goes back to Queued so it can be leased
    // again, and the dead grant stops counting as held work.
    let stale: Vec<(String, String)> = s
        .assignments
        .iter()
        .filter(|(_, g)| {
            !terminal(&s.jobs[&g.assignment.job_id].state)
                && if g.acknowledged {
                    g.lease_until
                } else {
                    g.assignment.expires_at
                } <= now
        })
        .map(|(id, g)| (id.clone(), g.assignment.job_id.clone()))
        .collect();
    for (assignment_id, job_id) in stale {
        let Some(job) = s.jobs.get_mut(&job_id) else {
            continue;
        };
        if job.assignment_id.as_deref() != Some(assignment_id.as_str()) {
            continue;
        }
        job.state = JobState::Queued;
        job.assignment_id = None;
        job.attempt_id = None;
        job.lease_id = None;
    }
    let live: BTreeSet<String> = s
        .assignments
        .iter()
        .filter(|(_, g)| {
            !terminal(&s.jobs[&g.assignment.job_id].state)
                && if g.acknowledged {
                    g.lease_until > now
                } else {
                    g.assignment.expires_at > now
                }
        })
        .map(|(id, _)| id.clone())
        .collect();
    let held = s
        .assignments
        .values()
        .filter(|g| g.assignment.worker_id == worker && live.contains(&g.assignment.assignment_id))
        .count() as i64;
    if held + node.info.direct_active >= node.info.capacity {
        return Ok(None);
    }
    // Private workers only serve their owner's jobs; ownerless (pre-upgrade)
    // jobs only go to public workers (design §2 safe default).
    let (worker_owner, worker_public) = ownership
        .get(worker)
        .map(|(owner, public)| (Some(owner.clone()), *public))
        .unwrap_or((None, true));
    let next = s
        .jobs
        .values()
        .filter(|j| {
            j.state == JobState::Queued
                && j.assignment_id.as_ref().is_none_or(|id| !live.contains(id))
                && worker_supports_request(&node.info, &j.request)
                && match (worker_public, s.owners.get(&j.job_id)) {
                    (true, _) => true,
                    (false, Some(owner)) => Some(owner) == worker_owner.as_ref(),
                    (false, None) => false,
                }
        })
        .min_by_key(|j| j.submitted_at.clone())
        .map(|j| j.job_id.clone());
    let Some(job_id) = next else { return Ok(None) };
    let r = s.jobs.get_mut(&job_id).unwrap();
    let a = Assignment {
        assignment_id: id(),
        attempt_id: id(),
        lease_id: id(),
        job_id: job_id.clone(),
        worker_id: worker.into(),
        instance_id: instance.into(),
        manager_epoch: s.epoch.clone(),
        request_sha256: digest(&r.request),
        expires_at: seconds() + 30.0,
        request: r.request.clone(),
    };
    r.assignment_id = Some(a.assignment_id.clone());
    r.attempt_id = Some(a.attempt_id.clone());
    r.lease_id = Some(a.lease_id.clone());
    r.worker_id = worker.into();
    r.instance_id = instance.into();
    r.board_id = node.info.board_id.clone();
    s.assignments.insert(
        a.assignment_id.clone(),
        Grant {
            assignment: a.clone(),
            acknowledged: false,
            lease_until: 0.0,
        },
    );
    Ok(Some(a))
}
pub fn router(manager: Arc<Manager>) -> Router {
    let metrics = manager.console.clone();
    // Per-route permission binding (design D8): every business route carries an
    // explicit require(); resource-level ownership is checked inside handlers.
    macro_rules! require {
        ($p:expr) => {{
            let m = manager.clone();
            axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let m = m.clone();
                    async move { auth::guard(&m, req, next, $p).await }
                },
            )
        }};
    }
    let require_user = {
        let m = manager.clone();
        axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let m = m.clone();
                async move { auth::guard_user(&m, req, next).await }
            },
        )
    };
    let jobs_write = post(submit).route_layer(require!(auth::Permission::JobSubmit));
    let jobs_read = get(list).route_layer(require!(auth::Permission::JobReadSelf));
    let job_read = get(job).route_layer(require!(auth::Permission::JobReadSelf));
    let job_cancel = delete(cancel).route_layer(require!(auth::Permission::JobCancelSelf));
    let cluster_register = post(register).route_layer(require!(auth::Permission::WorkerRegister));
    let cluster_claim = post(claim).route_layer(require!(auth::Permission::WorkerExecute));
    let cluster_ack = post(ack).route_layer(require!(auth::Permission::WorkerExecute));
    let cluster_events = post(events).route_layer(require!(auth::Permission::WorkerExecute));
    let cluster_renew = post(renew).route_layer(require!(auth::Permission::WorkerExecute));
    let workers_write = post(workers::routes::create).route_layer(require_user.clone());
    let workers_list = get(workers::routes::list).route_layer(require_user.clone());
    let worker_rotate = post(workers::routes::rotate).route_layer(require_user.clone());
    let worker_delete = delete(workers::routes::delete).route_layer(require_user.clone());
    let claims_list = get(workers::claim::list_claims).route_layer(require_user.clone());
    let claim_approve = post(workers::claim::approve).route_layer(require_user.clone());
    let claim_deny = post(workers::claim::deny).route_layer(require_user.clone());
    Router::new()
        .route("/jobs", jobs_write.merge(jobs_read))
        .route("/jobs/{id}", job_read.merge(job_cancel))
        .merge(auth::routes::router())
        .route("/workers", workers_write.merge(workers_list))
        .route("/workers/{id}/tokens", worker_rotate)
        .route(
            "/workers/{id}",
            get(workers::routes::get_one).delete(worker_delete),
        )
        .route("/cluster/workers/claim", post(workers::claim::begin))
        .route(
            "/cluster/workers/claim/{device_code}",
            get(workers::claim::poll),
        )
        .route("/claims", claims_list)
        .route("/claims/{code}/approve", claim_approve)
        .route("/claims/{code}/deny", claim_deny)
        .route("/claim", get(claim_page))
        .route("/metrics", get(observability::metrics))
        .route("/observability/summary", get(observability::summary))
        .route("/observability/targets", get(observability::targets))
        .route("/observability/range", get(observability::range))
        .route("/results", get(observability::results))
        .route("/leaderboard", get(observability::leaderboard))
        .route("/console/bootstrap", get(console_api::bootstrap))
        .route("/console/facilities", get(console_api::facilities))
        .route("/console/capabilities", get(console_api::capabilities))
        .route("/console/features", get(console_api::features))
        .route("/console/instance", get(console_api::instance))
        .route(
            "/healthz",
            get(|| async {
                Json(json!({"ok":true,"service":"rvbench-manager","protocol_version":"1.0.0"}))
            }),
        )
        .route("/cluster/workers", get(workers))
        .route("/cluster/workers/register", cluster_register)
        .route(
            "/cluster/workers/{id}/drain",
            post(drain).route_layer(require_user.clone()),
        )
        .route("/cluster/assignments/claim", cluster_claim)
        .route("/cluster/assignments/{id}/ack", cluster_ack)
        .route("/cluster/assignments/{id}/events", cluster_events)
        .route("/cluster/leases/{id}/renew", cluster_renew)
        .route(
            "/ui",
            get(|| async { Html(rvbench_protocol::CONSOLE_HTML) }),
        )
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            metrics,
            console::http_metrics,
        ))
        .with_state(manager)
}
async fn submit(
    State(m): State<Arc<Manager>>,
    principal: Option<Extension<Principal>>,
    RawJson(v): RawJson,
) -> Result<impl IntoResponse, ApiError> {
    let principal = principal.map(|Extension(p)| p);
    let sub = principal.as_ref().map(|p| p.sub.clone());
    let r = m.submit(decode("JobRequest", v)?, sub).await?;
    if let Some(p) = &principal {
        auth::audit::record(
            &m.auth,
            Some(&p.sub),
            Some(&p.login),
            "job.submit",
            Some(&r.job_id),
            "ok",
            None,
        )
        .await;
    }
    Ok((StatusCode::ACCEPTED, Json(r)))
}
async fn claim_page() -> impl IntoResponse {
    Html(workers::CLAIM_HTML)
}
async fn register(
    State(m): State<Arc<Manager>>,
    principal: Option<Extension<Principal>>,
    RawJson(v): RawJson,
) -> Result<Json<Value>, ApiError> {
    let info: WorkerRegistration = decode("WorkerRegistration", v)?;
    if let Some(Extension(p)) = &principal
        && p.is_worker()
        && p.sub != format!("worker:{}", info.worker_id)
    {
        // A worker token registers exactly its own id (design §2).
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "worker_id does not match the token".into(),
        ));
    }
    if m.auth.workers.get(&info.worker_id).is_some() {
        let now = seconds();
        m.auth.workers.set_last_seen(&info.worker_id, now);
        m.auth
            .heartbeats
            .lock()
            .unwrap()
            .insert(info.worker_id.clone(), now);
    }
    Ok(Json(m.register(info).await?))
}
async fn claim(State(m): State<Arc<Manager>>, RawJson(v): RawJson) -> Result<Response, ApiError> {
    match m.claim(decode("ClaimRequest", v)?).await? {
        Some(a) => Ok(Json(a).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}
async fn ack(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    RawJson(v): RawJson,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(m.acknowledge(id, decode("Ack", v)?, false).await?))
}
async fn renew(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    RawJson(v): RawJson,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(m.acknowledge(id, decode("Ack", v)?, true).await?))
}
async fn events(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    RawJson(v): RawJson,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(m.receive(id, decode("JobEvent", v)?).await?))
}
async fn workers(
    State(m): State<Arc<Manager>>,
    principal: Option<Extension<Principal>>,
    Query(q): Query<Full>,
) -> Result<Json<Value>, ApiError> {
    // Anonymous sees public runtime state; a login adds own private workers; admin
    // can request the unredacted view (design §2).
    let viewer = principal.map(|Extension(p)| p);
    let is_admin = viewer.as_ref().is_some_and(|p| p.is_admin);
    let full = is_admin && q.full.unwrap_or(false);
    let viewer_sub = viewer.as_ref().map(|p| p.sub.clone());
    let registry = m.auth.workers.clone();
    Ok(Json(m.store.tx(move |s|Ok(json!(s.workers.values().filter(|n| {
        let record = registry.get(&n.info.worker_id);
        let public = record.as_ref().is_none_or(|r| r.is_public());
        let owner_sub = record.as_ref().map(|r| r.owner_sub.clone());
        public || is_admin || match (&viewer_sub, &owner_sub) {
            (Some(v), Some(o)) => v == o,
            (Some(v), None) => v == "org:rvbench",
            _ => false,
        }
    }).map(|n| {
    let grants:Vec<_>=s.assignments.values().filter(|g|g.assignment.worker_id==n.info.worker_id&&!terminal(&s.jobs[&g.assignment.job_id].state)).map(|g|json!({"assignment":g.assignment,"acknowledged":g.acknowledged,"lease_until":g.lease_until,"uncertain":if g.acknowledged {g.lease_until<seconds()} else {g.assignment.expires_at<seconds()}})).collect();
    let mut info=serde_json::to_value(&n.info).unwrap();
    if !full { info["url"]=json!(""); info["observability"]=Value::Null; }
    let owner=registry.get(&n.info.worker_id).map(|r|json!({"sub":r.owner_sub,"login":r.owner_login})).unwrap_or(json!({"sub":"org:rvbench","login":"rvbench"}));
    json!({"worker":info,"owner":owner,"last_seen":n.last_seen,"online":seconds()-n.last_seen<=30.0,"drained":n.drained,"assignments":grants})
}).collect::<Vec<_>>()))).await?))
}
#[derive(Deserialize, Default)]
struct Full {
    full: Option<bool>,
}
async fn drain(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    principal: Option<Extension<Principal>>,
) -> Result<Json<Value>, ApiError> {
    // owner (worker:manage:self), admin (worker:manage:all), or the worker itself;
    // a foreign private worker drains into 404 (design §2).
    if let Some(Extension(p)) = &principal {
        let allowed = p.is_admin
            || p.sub == format!("worker:{id}")
            || m.auth
                .workers
                .get(&id)
                .is_none_or(|r| r.owner_sub == p.sub || r.is_public());
        if !allowed {
            return Err(ApiError::missing());
        }
    }
    Ok(Json(
        m.store
            .tx(move |s| {
                let n = s.workers.get_mut(&id).ok_or_else(ApiError::missing)?;
                n.drained = true;
                Ok(json!({"drained":true}))
            })
            .await?,
    ))
}
async fn list(
    State(m): State<Arc<Manager>>,
    principal: Option<Extension<Principal>>,
) -> Result<Json<Vec<JobRecord>>, ApiError> {
    // Logged-in users see only their own jobs; admin sees everything (design §2).
    // Anonymous (mode=off/warn) keeps the pre-auth behavior.
    let (sub, all) = match principal {
        Some(Extension(p)) => (Some(p.sub), p.is_admin),
        None => (None, true),
    };
    Ok(Json(
        m.store
            .tx(move |s| {
                let mut records: Vec<_> = s
                    .jobs
                    .values()
                    .filter(|j| {
                        all || s
                            .owners
                            .get(&j.job_id)
                            .is_some_and(|o| Some(o) == sub.as_ref())
                    })
                    .cloned()
                    .collect();
                records.sort_by(|a, b| b.submitted_at.cmp(&a.submitted_at));
                records.truncate(100);
                Ok(records)
            })
            .await?,
    ))
}
#[derive(Deserialize, Default)]
struct Wait {
    wait: Option<u64>,
}
async fn job(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    Query(q): Query<Wait>,
    principal: Option<Extension<Principal>>,
) -> Result<Json<JobRecord>, ApiError> {
    // Owner or admin; anyone else gets 404 so job ids cannot be enumerated (design §2).
    if let Some(Extension(p)) = &principal
        && !p.is_admin
        && m.auth.config.mode == auth::AuthMode::Enforce
    {
        let owner = m
            .store
            .tx({
                let id = id.clone();
                move |s| Ok(s.owners.get(&id).cloned())
            })
            .await?;
        if owner.as_deref() != Some(p.sub.as_str()) {
            return Err(ApiError::missing());
        }
    }
    let until = Instant::now() + Duration::from_secs(q.wait.unwrap_or(0).min(25));
    loop {
        let id = id.clone();
        let r = m
            .store
            .tx(move |s| s.jobs.get(&id).cloned().ok_or_else(ApiError::missing))
            .await?;
        if terminal(&r.state) || Instant::now() >= until {
            return Ok(Json(r));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
async fn cancel(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
    principal: Option<Extension<Principal>>,
) -> Result<Json<JobRecord>, ApiError> {
    if let Some(Extension(p)) = &principal
        && !p.is_admin
        && m.auth.config.mode == auth::AuthMode::Enforce
    {
        let owner = m
            .store
            .tx({
                let id = id.clone();
                move |s| Ok(s.owners.get(&id).cloned())
            })
            .await?;
        if owner.as_deref() != Some(p.sub.as_str()) {
            return Err(ApiError::missing());
        }
    }
    let r = m
        .store
        .tx(move |s| {
            let r = s.jobs.get_mut(&id).ok_or_else(ApiError::missing)?;
            if r.state != JobState::Queued || r.assignment_id.is_some() {
                return Err(ApiError::conflict(
                    "only unassigned queued jobs can be canceled",
                ));
            }
            r.state = JobState::Canceled;
            r.finished_at = Some(now());
            Ok(r.clone())
        })
        .await?;
    if let Some(Extension(p)) = &principal {
        auth::audit::record(
            &m.auth,
            Some(&p.sub),
            Some(&p.login),
            "job.cancel",
            Some(&r.job_id),
            "ok",
            None,
        )
        .await;
    }
    Ok(Json(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn registration(
        worker_id: &str,
        instance: String,
        delivery: &str,
        url: &str,
    ) -> WorkerRegistration {
        serde_json::from_value(json!({
            "worker_id": worker_id,
            "board_id": "board",
            "instance_id": instance,
            "backend": "k3",
            "kinds": ["correctness"],
            "delivery": delivery,
            "url": url,
            "capacity": 1,
            "direct_active": 0,
            "ready": true,
            "environment": {"ops": ["add"], "dtypes": ["float32"]},
            "protocol_version": "1.0.0"
        }))
        .unwrap()
    }
    fn claim_for(w: &WorkerRegistration) -> ClaimRequest {
        ClaimRequest {
            worker_id: w.worker_id.clone(),
            instance_id: w.instance_id.clone(),
            request_id: id(),
            wait_s: 0,
        }
    }
    #[tokio::test]
    async fn push_worker_retries_the_same_attempt_and_never_claims() {
        let temp = tempfile::tempdir().unwrap();
        let m = Manager::open(Config {
            victoriametrics: None,
            auth: None,
            worker_tokens: Vec::new(),
            listen: "127.0.0.1:0".into(),
            data_dir: temp.path().into(),
        })
        .await
        .unwrap();
        let delivered = Arc::new(std::sync::Mutex::new(Vec::<WorkerSubmission>::new()));
        let capture = delivered.clone();
        let app = Router::new().route(
            "/jobs",
            post(move |Json(s): Json<WorkerSubmission>| {
                let capture = capture.clone();
                async move {
                    capture.lock().unwrap().push(s);
                    StatusCode::ACCEPTED
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(axum::serve(listener, app).into_future());
        let worker = registration("push-1", id(), "push", &url);
        m.register(worker.clone()).await.unwrap();
        let request: JobRequest = serde_json::from_str(rvbench_protocol::EXAMPLE_JOB).unwrap();
        m.submit(request, None).await.unwrap();
        m.push_tick().await.unwrap();
        m.push_tick().await.unwrap();
        let seen = delivered.lock().unwrap().clone();
        assert_eq!(
            seen.len(),
            2,
            "an un-acked grant is re-delivered every tick"
        );
        let first = seen[0].assignment.as_ref().unwrap().attempt_id.clone();
        assert!(
            seen.iter()
                .all(|s| s.assignment.as_ref().unwrap().attempt_id == first),
            "a retry must reuse the attempt, not mint a new one"
        );
        // A push-only registration has no claim channel.
        assert!(
            m.claim(claim_for(&worker)).await.is_err(),
            "push-only workers are refused on the claim path"
        );
        server.abort();
    }
    #[tokio::test]
    async fn expired_lease_frees_the_slot_and_reissues_a_new_attempt() {
        let temp = tempfile::tempdir().unwrap();
        let m = Manager::open(Config {
            victoriametrics: None,
            auth: None,
            worker_tokens: Vec::new(),
            listen: "127.0.0.1:0".into(),
            data_dir: temp.path().into(),
        })
        .await
        .unwrap();
        let worker = registration("pull-1", id(), "pull", "http://127.0.0.1:1");
        m.register(worker.clone()).await.unwrap();
        let request: JobRequest = serde_json::from_str(rvbench_protocol::EXAMPLE_JOB).unwrap();
        m.submit(request, None).await.unwrap();
        let first = m
            .claim(claim_for(&worker))
            .await
            .unwrap()
            .expect("first grant");
        let ack = Ack {
            worker_id: worker.worker_id.clone(),
            instance_id: worker.instance_id.clone(),
            lease_id: first.lease_id.clone(),
            worker_job_id: first.job_id.clone(),
        };
        m.acknowledge(first.assignment_id.clone(), ack, false)
            .await
            .unwrap();
        assert!(
            m.claim(claim_for(&worker)).await.unwrap().is_none(),
            "a live lease keeps capacity=1 occupied"
        );
        let assignment_id = first.assignment_id.clone();
        m.store
            .tx(move |s| {
                s.assignments.get_mut(&assignment_id).unwrap().lease_until = seconds() - 60.0;
                Ok(())
            })
            .await
            .unwrap();
        let second = m
            .claim(claim_for(&worker))
            .await
            .unwrap()
            .expect("an expired lease must release the slot");
        assert_ne!(
            second.attempt_id, first.attempt_id,
            "re-leasing the job is a new attempt"
        );
        assert_eq!(second.job_id, first.job_id, "the same job is retried");
    }
}

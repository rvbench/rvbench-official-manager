//! Durable unified submission and scheduling. Push and pull call the same transaction.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use rvbench_protocol::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub mod observability;
use rvbench_protocol::console::{Console, LeaseView};
use std::{
    collections::BTreeMap,
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
    pub collection: std::sync::RwLock<CollectionHealth>,
    pub query_limit: tokio::sync::Semaphore,
    pub config: Config,
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
        Ok(Arc::new(Self {
            console,
            collection: std::sync::RwLock::new(serde_json::from_value(json!({"status":"unavailable","errors":["Waiting for VictoriaMetrics health check"]})).unwrap()),
            query_limit: tokio::sync::Semaphore::new(4),
            config,
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
                    .filter(|n| n.info.delivery != DeliveryMode::Pull)
                    .map(|n| n.info.clone())
                    .collect::<Vec<_>>())
            })
            .await?;
        for w in workers {
            let wid = w.worker_id.clone();
            let instance = w.instance_id.clone();
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
                        })
                        .map(|g| g.assignment.clone());
                    if pending.is_some() {
                        return Ok(pending);
                    }
                    allocate(s, &wid, &instance)
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
    pub async fn submit(&self, request: JobRequest) -> Result<JobRecord, ApiError> {
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
                s.jobs.insert(r.job_id.clone(), r.clone());
                Ok(r)
            })
            .await
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
        loop {
            let request = c.clone();
            let result = self
                .store
                .tx(move |s| {
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
                    let a = allocate(s, &request.worker_id, &request.instance_id)?;
                    // Empty receipts are recorded only once the long poll actually finishes.
                    if let Some(a) = &a {
                        s.claims.insert(
                            request.request_id,
                            (fingerprint, Some(a.assignment_id.clone())),
                        );
                    }
                    Ok(a)
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
) -> Result<Option<Assignment>, ApiError> {
    let node = s.workers.get(worker).ok_or_else(ApiError::missing)?;
    if node.info.instance_id != instance {
        return Err(ApiError::conflict("instance mismatch"));
    }
    if node.drained || !node.info.ready || seconds() - node.last_seen > 30.0 {
        return Ok(None);
    }
    let held = s
        .assignments
        .values()
        .filter(|g| {
            g.assignment.worker_id == worker && !terminal(&s.jobs[&g.assignment.job_id].state)
        })
        .count() as i64;
    if held + node.info.direct_active >= node.info.capacity {
        return Ok(None);
    }
    let next = s
        .jobs
        .values()
        .filter(|j| {
            j.state == JobState::Queued
                && j.assignment_id.is_none()
                && worker_supports_request(&node.info, &j.request)
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
    Router::new()
        .route("/metrics", get(observability::metrics))
        .route("/observability/summary", get(observability::summary))
        .route("/observability/targets", get(observability::targets))
        .route("/observability/range", get(observability::range))
        .route("/results", get(observability::results))
        .route("/leaderboard", get(observability::leaderboard))
        .route(
            "/healthz",
            get(|| async {
                Json(json!({"ok":true,"service":"rvbench-manager","protocol_version":"1.0.0"}))
            }),
        )
        .route("/jobs", post(submit).get(list))
        .route("/jobs/{id}", get(job).delete(cancel))
        .route("/cluster/workers", get(workers))
        .route("/cluster/workers/register", post(register))
        .route("/cluster/workers/{id}/drain", post(drain))
        .route("/cluster/assignments/claim", post(claim))
        .route("/cluster/assignments/{id}/ack", post(ack))
        .route("/cluster/assignments/{id}/events", post(events))
        .route("/cluster/leases/{id}/renew", post(renew))
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
    RawJson(v): RawJson,
) -> Result<impl IntoResponse, ApiError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(m.submit(decode("JobRequest", v)?).await?),
    ))
}
async fn register(
    State(m): State<Arc<Manager>>,
    RawJson(v): RawJson,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(m.register(decode("WorkerRegistration", v)?).await?))
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
async fn workers(State(m): State<Arc<Manager>>) -> Result<Json<Value>, ApiError> {
    Ok(Json(m.store.tx(|s|Ok(json!(s.workers.values().map(|n| {
    let grants:Vec<_>=s.assignments.values().filter(|g|g.assignment.worker_id==n.info.worker_id&&!terminal(&s.jobs[&g.assignment.job_id].state)).map(|g|json!({"assignment":g.assignment,"acknowledged":g.acknowledged,"lease_until":g.lease_until,"uncertain":if g.acknowledged {g.lease_until<seconds()} else {g.assignment.expires_at<seconds()}})).collect();
    json!({"worker":n.info,"last_seen":n.last_seen,"online":seconds()-n.last_seen<=30.0,"drained":n.drained,"assignments":grants})
}).collect::<Vec<_>>()))).await?))
}
async fn drain(
    State(m): State<Arc<Manager>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
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
async fn list(State(m): State<Arc<Manager>>) -> Result<Json<Vec<JobRecord>>, ApiError> {
    Ok(Json(
        m.store
            .tx(|s| {
                let mut records: Vec<_> = s.jobs.values().cloned().collect();
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
) -> Result<Json<JobRecord>, ApiError> {
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
) -> Result<Json<JobRecord>, ApiError> {
    Ok(Json(
        m.store
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
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn push_pull_race_and_expired_execution_never_allocate_twice() {
        let temp = tempfile::tempdir().unwrap();
        let m = Manager::open(Config {
            victoriametrics: None,
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
        let worker:WorkerRegistration=serde_json::from_value(json!({"worker_id":"hybrid","board_id":"board","instance_id":id(),"backend":"k3","kinds":["correctness"],"delivery":"hybrid","url":url,"capacity":1,"direct_active":0,"ready":true,"environment":{"ops":["add"],"dtypes":["float32"]},"protocol_version":"1.0.0"})).unwrap();
        m.register(worker.clone()).await.unwrap();
        let request: JobRequest = serde_json::from_str(rvbench_protocol::EXAMPLE_JOB).unwrap();
        m.submit(request.clone()).await.unwrap();
        let claim = ClaimRequest {
            worker_id: worker.worker_id.clone(),
            instance_id: worker.instance_id.clone(),
            request_id: id(),
            wait_s: 0,
        };
        let (push, pull) = tokio::join!(m.push_tick(), m.claim(claim));
        push.unwrap();
        let pull = pull.unwrap();
        // Hybrid may deliver the same grant over both channels before its ACK.
        // Persistent admission deduplicates those deliveries at the worker.
        let mut attempts: std::collections::BTreeSet<String> = delivered
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.assignment.as_ref().unwrap().attempt_id.clone())
            .collect();
        if let Some(a) = &pull {
            attempts.insert(a.attempt_id.clone());
        }
        assert_eq!(attempts.len(), 1);
        let assignment = m
            .store
            .tx(|s| {
                assert_eq!(s.assignments.len(), 1);
                Ok(s.assignments.values().next().unwrap().assignment.clone())
            })
            .await
            .unwrap();
        m.push_tick().await.unwrap();
        assert!(
            delivered
                .lock()
                .unwrap()
                .iter()
                .all(|s| s.assignment.as_ref().unwrap().attempt_id == assignment.attempt_id)
        );
        let ack = Ack {
            worker_id: worker.worker_id.clone(),
            instance_id: worker.instance_id.clone(),
            lease_id: assignment.lease_id.clone(),
            worker_job_id: assignment.job_id.clone(),
        };
        m.acknowledge(assignment.assignment_id.clone(), ack, false)
            .await
            .unwrap();
        m.store
            .tx(move |s| {
                s.assignments
                    .get_mut(&assignment.assignment_id)
                    .unwrap()
                    .lease_until = seconds() - 60.0;
                Ok(())
            })
            .await
            .unwrap();
        m.submit(request).await.unwrap();
        assert!(
            m.claim(ClaimRequest {
                worker_id: worker.worker_id,
                instance_id: worker.instance_id,
                request_id: id(),
                wait_s: 0
            })
            .await
            .unwrap()
            .is_none()
        );
        assert_eq!(m.store.tx(|s| Ok(s.assignments.len())).await.unwrap(), 1);
        server.abort();
    }
}

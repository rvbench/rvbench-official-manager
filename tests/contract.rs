use rvbench_manager::{Config, Manager};
use rvbench_protocol::*;
use serde_json::{Value, json};
fn request() -> JobRequest {
    serde_json::from_str(rvbench_protocol::EXAMPLE_JOB).unwrap()
}
fn registration() -> WorkerRegistration {
    serde_json::from_value(json!({"worker_id":"test","board_id":"board","instance_id":id(),"backend":"k3","kinds":["func","correctness"],"delivery":"hybrid","url":"http://127.0.0.1:18801","capacity":1,"direct_active":0,"ready":true,"environment":{"ops":["add","abs"],"dtypes":["float32"]},"protocol_version":"1.0.0"})).unwrap()
}
#[tokio::test]
async fn claims_match_implementation_capabilities_on_either_hardware() {
    for hardware in [BackendId::K1, BackendId::K3] {
        let temp = tempfile::tempdir().unwrap();
        let m = Manager::open(Config {
            victoriametrics: None,
            listen: "127.0.0.1:0".into(),
            data_dir: temp.path().into(),
        })
        .await
        .unwrap();
        let mut c = registration();
        c.backend = hardware.clone();
        c.environment = serde_json::from_value(json!({"implementations":{
            "native-c":{"ready":true,"ops":["add"],"dtypes":["float32"]},
            "triton":{"ready":false,"ops":["add"],"dtypes":["float32","float16"]}
        }}))
        .unwrap();
        m.register(c.clone()).await.unwrap();
        let mut t = c.clone();
        t.worker_id = "triton-worker".into();
        t.instance_id = id();
        t.environment = serde_json::from_value(json!({"implementations":{
            "triton":{"ready":true,"ops":["add"],"dtypes":["float32","float16"]}
        }}))
        .unwrap();
        m.register(t.clone()).await.unwrap();
        let mut r = request();
        r.backend = hardware;
        r.implementation = Some(KernelImplementation::Triton);
        r.dtype = JobRequestDtype::Float16;
        let triton_job = m.submit(r.clone()).await.unwrap();
        r.implementation = Some(KernelImplementation::NativeC);
        let unsupported_dtype = m.submit(r.clone()).await.unwrap();
        r.dtype = JobRequestDtype::Float32;
        let c_job = m.submit(r).await.unwrap();
        let claim = |w: &WorkerRegistration| ClaimRequest {
            worker_id: w.worker_id.clone(),
            instance_id: w.instance_id.clone(),
            request_id: id(),
            wait_s: 0,
        };
        let a = m.claim(claim(&c)).await.unwrap().unwrap();
        assert_eq!(a.job_id, c_job.job_id);
        assert_ne!(a.job_id, unsupported_dtype.job_id);
        let a = m.claim(claim(&t)).await.unwrap().unwrap();
        assert_eq!(a.job_id, triton_job.job_id);
    }
}
#[tokio::test]
async fn atomic_claims_fencing_replays_and_durable_results() {
    let temp = tempfile::tempdir().unwrap();
    let config = Config {
        victoriametrics: None,
        listen: "127.0.0.1:0".into(),
        data_dir: temp.path().into(),
    };
    let m = Manager::open(config.clone()).await.unwrap();
    let w = registration();
    m.register(w.clone()).await.unwrap();
    let mut req = request();
    req.op = "add".into();
    req.kind = JobKind::Correctness;
    req.client_request_id = Some("same".into());
    let j = m.submit(req.clone()).await.unwrap();
    let counters_before = m.console.snapshot().metrics.clone();
    assert_eq!(m.submit(req.clone()).await.unwrap().job_id, j.job_id);
    assert_eq!(counters_before, m.console.snapshot().metrics);
    let mut changed = req.clone();
    changed.seed += 1;
    assert_eq!(m.submit(changed).await.unwrap_err().0, 409);
    let c = ClaimRequest {
        worker_id: w.worker_id.clone(),
        instance_id: w.instance_id.clone(),
        request_id: id(),
        wait_s: 0,
    };
    let c2 = ClaimRequest {
        request_id: id(),
        ..c.clone()
    };
    let (a, b) = tokio::join!(m.claim(c.clone()), m.claim(c2));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.is_some() as u8 + b.is_some() as u8, 1);
    let a = a.or(b).unwrap();
    if let Some(replay) = m.claim(c.clone()).await.unwrap() {
        assert_eq!(replay.assignment_id, a.assignment_id);
    }
    let mut wrong = c.clone();
    wrong.wait_s = 1;
    assert_eq!(m.claim(wrong).await.unwrap_err().0, 409);
    let mut ack = Ack {
        worker_id: w.worker_id.clone(),
        instance_id: w.instance_id.clone(),
        lease_id: id(),
        worker_job_id: j.job_id.clone(),
    };
    assert_eq!(
        m.acknowledge(a.assignment_id.clone(), ack.clone(), false)
            .await
            .unwrap_err()
            .0,
        409
    );
    ack.lease_id = a.lease_id.clone();
    m.acknowledge(a.assignment_id.clone(), ack.clone(), false)
        .await
        .unwrap();
    m.acknowledge(a.lease_id.clone(), ack, true).await.unwrap();
    let phase:PhaseResult=serde_json::from_value(json!({"status":"passed","details":{},"artifacts":[{"path":"evaluation.json","sha256":"0".repeat(64),"size_bytes":1}]})).unwrap();
    let mut r = j;
    let logical_submitted_at = r.submitted_at.clone();
    r.submitted_at = "2030-01-01T00:00:00Z".into();
    r.state = JobState::Done;
    r.compilation = Some(phase.clone());
    r.evaluation = Some(phase);
    r.worker_id = w.worker_id;
    r.board_id = w.board_id;
    r.instance_id = w.instance_id;
    r.assignment_id = Some(a.assignment_id.clone());
    r.attempt_id = Some(a.attempt_id.clone());
    r.lease_id = Some(a.lease_id.clone());
    r.finished_at = Some(now());
    let e = JobEvent {
        assignment: a.clone(),
        event_id: format!("{}:terminal", a.attempt_id),
        event_seq: 1,
        record: r,
    };
    m.receive(a.assignment_id.clone(), e.clone()).await.unwrap();
    assert_eq!(
        m.console
            .snapshot()
            .results
            .iter()
            .find(|r| r.job_id == a.job_id)
            .unwrap()
            .submitted_at,
        logical_submitted_at
    );
    assert_eq!(
        m.receive(a.assignment_id.clone(), e.clone()).await.unwrap()["duplicate"],
        true
    );
    let mut forged = e.clone();
    forged.record.logs = "changed".into();
    assert_eq!(
        m.receive(a.assignment_id.clone(), forged)
            .await
            .unwrap_err()
            .0,
        409
    );
    drop(m);
    let m = Manager::open(config).await.unwrap();
    assert_eq!(
        m.receive(a.assignment_id, e).await.unwrap()["duplicate"],
        true
    );
}
#[tokio::test]
async fn unauthenticated_http_validates_contract_and_role_matching() {
    let temp = tempfile::tempdir().unwrap();
    let m = Manager::open(Config {
        victoriametrics: None,
        listen: "127.0.0.1:0".into(),
        data_dir: temp.path().into(),
    })
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task =
        tokio::spawn(axum::serve(listener, rvbench_manager::router(m.clone())).into_future());
    let client = reqwest::Client::new();
    let mut w = registration();
    w.kinds = vec![JobKind::Performance];
    assert!(
        client
            .post(format!("{base}/cluster/workers/register"))
            .json(&w)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let mut request: Value = serde_json::to_value(request()).unwrap();
    request["op"] = json!("add");
    request["kind"] = json!("correctness");
    let response = client
        .post(format!("{base}/jobs"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    validate("JobRecord", &response.json::<Value>().await.unwrap()).unwrap();
    let duplicate = format!(
        "{{\"backend\":\"k3\",{}",
        serde_json::to_string(&request)
            .unwrap()
            .trim_start_matches('{')
    );
    assert_eq!(
        client
            .post(format!("{base}/jobs"))
            .header("Content-Type", "application/json")
            .body(duplicate)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    request["repetitions"] = json!(0);
    assert_eq!(
        client
            .post(format!("{base}/jobs"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let claim = ClaimRequest {
        worker_id: w.worker_id,
        instance_id: w.instance_id,
        request_id: id(),
        wait_s: 0,
    };
    assert!(m.claim(claim).await.unwrap().is_none());
    task.abort();
}

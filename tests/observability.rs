use rvbench_manager::{Config, Manager};
use rvbench_protocol::*;
use serde_json::{Value, json};
#[tokio::test]
async fn metric_outage_does_not_block_jobs_and_invalid_queries_are_rejected() {
    let t = tempfile::tempdir().unwrap();
    let m = Manager::open(Config {
        listen: "127.0.0.1:0".into(),
        data_dir: t.path().into(),
        victoriametrics: None,
    })
    .await
    .unwrap();
    m.update_collection().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = tokio::spawn(axum::serve(listener, rvbench_manager::router(m.clone())).into_future());
    let c = reqwest::Client::new();
    let request: JobRequest = serde_json::from_str(rvbench_protocol::EXAMPLE_JOB).unwrap();
    let j = m.submit(request).await.unwrap();
    let response = c
        .get(format!("{base}/observability/summary"))
        .send()
        .await
        .unwrap();
    let v: Value = response.json().await.unwrap();
    validate("ObservationSummary", &v).unwrap();
    assert_eq!(v["collection"]["status"], "unavailable");
    let metric = c.get(format!("{base}/metrics")).send().await.unwrap();
    assert!(
        metric.headers()["content-type"]
            .to_str()
            .unwrap()
            .contains("version=0.0.4")
    );
    let text = metric.text().await.unwrap();
    assert!(!text.contains(&j.job_id));
    assert!(text.contains("# TYPE rvbench_manager_jobs_submitted_total counter"));
    for path in [
        "/results?limit=0",
        "/results?offset=-1",
        "/observability/range?metric_id=unknown&start=1&end=2&step_seconds=30",
        "/observability/range?metric_id=cpu_percent&start=1&end=9999999&step_seconds=30",
    ] {
        assert!(
            c.get(format!("{base}{path}"))
                .send()
                .await
                .unwrap()
                .status()
                .is_client_error()
        );
    }
    let v: Value = c
        .get(format!(
            "{base}/observability/range?metric_id=cpu_percent&start=1&end=2&step_seconds=30"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    validate("MetricRange", &v).unwrap();
    assert_eq!(v["partial"], true);
    assert_eq!(v["series"], json!([]));
    let rows: Value = c
        .get(format!("{base}/results?limit=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    validate("ResultsPage", &rows).unwrap();
    assert_eq!(rows["total"], 1);
    assert_eq!(rows["items"][0]["job_id"], j.job_id);
    drop(c);
    app.abort();
    let _ = app.await;
    for _ in 0..100 {
        if std::sync::Arc::strong_count(&m) == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let before = m.console.snapshot().metrics.clone();
    drop(m);
    let m = Manager::open(Config {
        listen: "127.0.0.1:0".into(),
        data_dir: t.path().into(),
        victoriametrics: None,
    })
    .await
    .unwrap();
    assert_eq!(before, m.console.snapshot().metrics);
}

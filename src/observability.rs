use super::*;
use axum::http::header;
use std::collections::BTreeSet;

pub async fn metrics(State(m): State<Arc<Manager>>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        m.console.metrics(),
    )
}
pub async fn results(
    State(m): State<Arc<Manager>>,
    Query(q): Query<ResultQuery>,
) -> Result<Json<ResultsPage>, ApiError> {
    Ok(Json(m.console.results(q)?))
}
pub async fn leaderboard(
    State(m): State<Arc<Manager>>,
    Query(q): Query<LeaderboardQuery>,
) -> Result<Json<LeaderboardPage>, ApiError> {
    Ok(Json(m.console.leaderboard(q)?))
}
pub async fn summary(State(m): State<Arc<Manager>>) -> Json<ObservationSummary> {
    let mut h = m.collection.read().unwrap().clone();
    let (_, errors) = discovery(&m);
    if !errors.is_empty() {
        h.errors.extend(errors);
        if h.status == CollectionHealthStatus::Ok {
            h.status = CollectionHealthStatus::Degraded;
        }
    }
    Json(m.console.summary(h))
}
fn target(url: &str, labels: Value) -> Option<DiscoveryTarget> {
    let u = reqwest::Url::parse(url).ok()?;
    if !["http", "https"].contains(&u.scheme())
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return None;
    }
    let host = u.host()?;
    let address = format!("{}:{}", host, u.port_or_known_default()?);
    let mut l = labels;
    l["__scheme__"] = json!(u.scheme());
    l["__metrics_path__"] = json!(u.path());
    serde_json::from_value(json!({"targets":[address],"labels":l})).ok()
}
fn discovery(m: &Manager) -> (Vec<DiscoveryTarget>, Vec<String>) {
    let view = m.console.snapshot();
    let mut result = vec![];
    let mut errors = vec![];
    let mut hosts = BTreeMap::<String, (String, BTreeSet<String>)>::new();
    for n in &view.workers {
        let w = &n.worker;
        let Some(o) = &w.observability else {
            continue;
        };
        let url = format!("{}{}", w.url.trim_end_matches('/'), o.metrics_path);
        if let Some(t) = target(
            &url,
            json!({"job":"rvbench_workers","board_id":w.board_id,"worker_id":w.worker_id,"backend":w.backend}),
        ) {
            result.push(t);
        } else {
            errors.push(format!("Invalid metrics URL for {}", w.worker_id));
        }
        if let Some(url) = &o.host_metrics_url {
            let e = hosts
                .entry(w.board_id.clone())
                .or_insert((w.backend.to_string(), BTreeSet::new()));
            e.1.insert(url.clone());
        }
    }
    for (board, (backend, urls)) in hosts {
        if urls.len() != 1 {
            errors.push(format!(
                "Conflicting host exporter declarations for {board}"
            ));
            continue;
        }
        if let Some(t) = target(
            urls.first().unwrap(),
            json!({"job":"rvbench_nodes","board_id":board,"backend":backend}),
        ) {
            result.push(t);
        } else {
            errors.push(format!("Invalid host exporter URL for {board}"));
        }
    }
    (result, errors)
}
pub async fn targets(State(m): State<Arc<Manager>>) -> Json<Vec<DiscoveryTarget>> {
    Json(discovery(&m).0)
}
impl Manager {
    pub async fn update_collection(&self) {
        if self.config.victoriametrics.is_none() {
            *self.collection.write().unwrap() = serde_json::from_value(
                json!({"status":"unavailable","errors":["VictoriaMetrics is not configured"]}),
            )
            .unwrap();
            return;
        }
        let mut result = self
            .vm_json("/api/v1/targets", &[])
            .await
            .and_then(collection_health);
        if let Ok(h) = &mut result {
            let ts = h.targets.get_or_insert_with(Vec::new);
            for expected in discovery(self).0 {
                let labels = &expected.labels.additional_properties;
                let scheme = labels
                    .get("__scheme__")
                    .map(String::as_str)
                    .unwrap_or("http");
                let path = labels
                    .get("__metrics_path__")
                    .map(String::as_str)
                    .unwrap_or("/metrics");
                for address in &expected.targets {
                    let url = format!("{scheme}://{address}{path}");
                    if !ts.iter().any(|t| t.url == url) {
                        h.errors
                            .push(format!("Waiting for discovered target {url}"));
                        ts.push(serde_json::from_value(json!({"url":url,"job":labels.get("job"),"board_id":labels.get("board_id"),"worker_id":labels.get("worker_id"),"up":false,"error":"Waiting for service discovery"})).unwrap());
                    }
                }
            }
            h.targets_total = Some(ts.len() as i64);
            if !h.errors.is_empty() {
                h.status = CollectionHealthStatus::Degraded;
            }
        }
        let mut h = self.collection.write().unwrap();
        match result {
            Ok(next) => *h = next,
            Err(e) => {
                h.status = CollectionHealthStatus::Unavailable;
                h.errors = vec![format!("VictoriaMetrics: {e}")];
            }
        }
    }
    async fn vm_json(&self, path: &str, params: &[(&str, String)]) -> anyhow::Result<Value> {
        let base = self
            .config
            .victoriametrics
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("VictoriaMetrics is not configured"))?;
        let mut response = self
            .client
            .get(format!("{}{path}", base.trim_end_matches('/')))
            .query(params)
            .send()
            .await?
            .error_for_status()?;
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                data.len() + chunk.len() <= 2 * 1024 * 1024,
                "metric response exceeds 2 MiB"
            );
            data.extend_from_slice(&chunk);
        }
        let v: Value = serde_json::from_slice(&data)?;
        anyhow::ensure!(v["status"] == "success", "VictoriaMetrics query failed");
        Ok(v)
    }
}
fn collection_health(v: Value) -> anyhow::Result<CollectionHealth> {
    let rows = v["data"]["activeTargets"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Invalid target status response"))?;
    let mut targets = vec![];
    let mut errors = vec![];
    let mut up = 0;
    for row in rows {
        let healthy = row["health"] == "up";
        if healthy {
            up += 1;
        }
        let reason = row["lastError"].as_str().unwrap_or("");
        let error = if !healthy && reason.is_empty() {
            "Waiting for first scrape"
        } else {
            reason
        };
        if !healthy {
            errors.push(format!(
                "{}: {}",
                row["scrapeUrl"].as_str().unwrap_or("unknown target"),
                error.chars().take(200).collect::<String>()
            ));
        }
        let mut t = json!({"url":row["scrapeUrl"],"job":row["labels"]["job"],"board_id":row["labels"]["board_id"],"worker_id":row["labels"]["worker_id"],"up":healthy,"error":error});
        if let Some(time) = row["lastScrape"].as_str().and_then(console::timestamp) {
            t["last_scrape_at"] = json!(time);
        }
        targets.push(serde_json::from_value::<CollectionTarget>(t)?);
    }
    if rows.is_empty() {
        errors.push("Waiting for scrape targets".into());
    }
    Ok(serde_json::from_value(
        json!({"status":if errors.is_empty(){"ok"}else{"degraded"},"errors":errors,"targets":targets,"targets_total":rows.len(),"targets_up":up,"last_success_at":seconds()}),
    )?)
}
fn grid_points(values: &Value, start: f64, end: f64, step: i64) -> Vec<Value> {
    let mut samples = BTreeMap::new();
    if let Some(vs) = values.as_array() {
        for p in vs {
            if let Some(t) = p[0].as_f64() {
                let value = p[1]
                    .as_str()
                    .and_then(|s| s.parse::<f64>().ok())
                    .filter(|x| x.is_finite());
                samples.insert((t * 1000.).round() as i64, value);
            }
        }
    }
    let mut points = vec![];
    let mut t = start;
    while t <= end {
        let mut p = json!({"timestamp":t});
        if let Some(Some(v)) = samples.get(&((t * 1000.).round() as i64)) {
            p["value"] = json!(v);
        }
        points.push(p);
        t += step as f64;
    }
    points
}
pub fn check_range(q: &RangeQuery) -> Result<(), ApiError> {
    validate("RangeQuery", &json!(q)).map_err(ApiError::bad)?;
    if !q.start.is_finite()
        || !q.end.is_finite()
        || q.start <= 0.
        || q.end < q.start
        || q.end - q.start > 86400.
        || (q.end - q.start) / q.step_seconds as f64 + 1. > 1800.
        || q.end > seconds() + 60.
    {
        return Err(ApiError::bad(
            "range must be finite, ordered, <=24h, <=1800 points and not in the future",
        ));
    }
    Ok(())
}
fn expression(q: &RangeQuery) -> (String, String, String) {
    let mut filter = String::new();
    for (key, v) in [("board_id", &q.board_id), ("worker_id", &q.worker_id)] {
        if let Some(v) = v {
            filter.push_str(&format!(",{key}=\"{}\"", console::escape(v)));
        }
    }
    let node = format!("job=\"rvbench_nodes\"{filter}");
    let worker = format!("job=\"rvbench_workers\"{filter}");
    let (expr, base, unit) = match q.metric_id.as_str() {
        "cpu_percent" => (
            format!(
                "100*(1-avg by(board_id)(rate(node_cpu_seconds_total{{{node},mode=\"idle\"}}[2m])))"
            ),
            format!("node_cpu_seconds_total{{{node},mode=\"idle\"}}"),
            "%",
        ),
        "x100_cpu_percent" | "a100_cpu_percent" => {
            let cpu = if q.metric_id.as_str() == "x100_cpu_percent" {
                "[0-7]"
            } else {
                "8|9|1[0-5]"
            };
            (
                format!(
                    "100*(1-avg by(board_id)(rate(node_cpu_seconds_total{{{node},backend=\"k3\",mode=\"idle\",cpu=~\"{cpu}\"}}[2m])))"
                ),
                format!("node_cpu_seconds_total{{{node},mode=\"idle\"}}"),
                "%",
            )
        }
        "memory_percent" => (
            format!(
                "100*(1-node_memory_MemAvailable_bytes{{{node}}}/node_memory_MemTotal_bytes{{{node}}})"
            ),
            format!("node_memory_MemAvailable_bytes{{{node}}}"),
            "%",
        ),
        "disk_percent" => (
            format!(
                "100*(1-node_filesystem_avail_bytes{{{node},mountpoint=\"/\"}}/node_filesystem_size_bytes{{{node},mountpoint=\"/\"}})"
            ),
            format!("node_filesystem_avail_bytes{{{node},mountpoint=\"/\"}}"),
            "%",
        ),
        "temperature_c" => (
            format!("max by(board_id)(node_hwmon_temp_celsius{{{node}}})"),
            format!("node_hwmon_temp_celsius{{{node}}}"),
            "°C",
        ),
        "load1" => (
            format!("node_load1{{{node}}}"),
            format!("node_load1{{{node}}}"),
            "load",
        ),
        "queue_depth" | "running" => {
            let state = if q.metric_id.as_str() == "running" {
                "running"
            } else {
                "queued"
            };
            (
                format!(
                    "sum by(board_id,worker_id)(rvbench_worker_jobs{{{worker},state=\"{state}\"}})"
                ),
                format!("rvbench_worker_jobs{{{worker}}}"),
                "jobs",
            )
        }
        "outbox" => (
            format!("rvbench_worker_outbox_pending{{{worker}}}"),
            format!("rvbench_worker_outbox_pending{{{worker}}}"),
            "events",
        ),
        "throughput" => (
            format!(
                "sum by(board_id,worker_id)(rate(rvbench_worker_jobs_completed_total{{{worker},state=\"done\"}}[15m]))*60"
            ),
            format!("rvbench_worker_jobs_completed_total{{{worker}}}"),
            "jobs/min",
        ),
        "submissions" => (
            format!(
                "sum by(board_id,worker_id)(increase(rvbench_worker_jobs_submitted_total{{{worker}}}[1h]))"
            ),
            format!("rvbench_worker_jobs_submitted_total{{{worker}}}"),
            "jobs/hour",
        ),
        "completed" => (
            format!(
                "sum by(board_id,worker_id,state)(increase(rvbench_worker_jobs_completed_total{{{worker}}}[1h]))"
            ),
            format!("rvbench_worker_jobs_completed_total{{{worker}}}"),
            "jobs/hour",
        ),
        _ => (
            format!("up{{job=~\"rvbench_.*\"{filter}}}"),
            format!("up{{job=~\"rvbench_.*\"{filter}}}"),
            "up",
        ),
    };
    (expr, base, unit.into())
}
pub async fn range(
    State(m): State<Arc<Manager>>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<MetricRange>, ApiError> {
    check_range(&q)?;
    let _permit = m.query_limit.try_acquire().map_err(|_| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many metric queries".into(),
        )
    })?;
    let (expr, base, unit) = expression(&q);
    let mut series = vec![];
    let mut errors = vec![];
    let query = m
        .vm_json(
            "/api/v1/query_range",
            &[
                ("query", expr),
                ("start", q.start.to_string()),
                ("end", q.end.to_string()),
                ("step", q.step_seconds.to_string()),
                ("max_lookback", "60s".into()),
            ],
        )
        .await;
    match query {
        Err(e) => errors.push(e.to_string()),
        Ok(v) => {
            let times = m
                .vm_json(
                    "/api/v1/query",
                    &[(
                        "query",
                        format!("max by(board_id,worker_id)(timestamp({base}))"),
                    )],
                )
                .await;
            if let Err(e) = &times {
                errors.push(e.to_string());
            }
            if let Some(rows) = v["data"]["result"].as_array() {
                for row in rows {
                    let labels = &row["metric"];
                    let last = times
                        .as_ref()
                        .ok()
                        .and_then(|v| v["data"]["result"].as_array())
                        .and_then(|a| {
                            a.iter().find(|r| {
                                r["metric"]["board_id"] == labels["board_id"]
                                    && r["metric"]["worker_id"] == labels["worker_id"]
                            })
                        })
                        .and_then(|r| r["value"][1].as_str()?.parse::<f64>().ok())
                        .filter(|x| x.is_finite());
                    let points = grid_points(&row["values"], q.start, q.end, q.step_seconds);
                    let mut s = json!({"labels":labels,"points":points,"stale":last.is_none_or(|t|seconds()-t>90.)});
                    if let Some(t) = last {
                        s["last_sample_at"] = json!(t);
                    }
                    series.push(s);
                }
            }
        }
    }
    Ok(Json(decode(
        "MetricRange",
        json!({"metric_id":q.metric_id,"unit":unit,"generated_at":seconds(),"step_seconds":q.step_seconds,"series":series,"partial":!errors.is_empty(),"errors":errors}),
    )?))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn healthy_database_does_not_hide_failed_exporter() {
        let h=collection_health(json!({"data":{"activeTargets":[{"health":"up","scrapeUrl":"http://a/metrics","labels":{"job":"worker"},"lastScrape":"2026-10-17T01:00:00Z","lastError":""},{"health":"down","scrapeUrl":"http://b/metrics","labels":{"job":"node"},"lastError":"connection refused"}]}})).unwrap();
        assert_eq!(h.status, CollectionHealthStatus::Degraded);
        assert_eq!(h.targets_up, Some(1));
        validate("CollectionHealth", &json!(h)).unwrap();
    }
    #[test]
    fn missing_and_nonfinite_points_stay_gaps() {
        let p = grid_points(&json!([[30, "1"], [90, "NaN"], [120, "0"]]), 30., 120., 30);
        assert_eq!(p.len(), 4);
        assert_eq!(p[0]["value"], 1.);
        assert!(p[1].get("value").is_none());
        assert!(p[2].get("value").is_none());
        assert_eq!(p[3]["value"], 0.);
        let hourly = grid_points(&json!([[61, "5"], [3661, "6"]]), 61., 3661., 3600);
        assert_eq!(hourly[0]["timestamp"], 61.);
        assert_eq!(hourly[0]["value"], 5.);
        assert_eq!(hourly[1]["value"], 6.);
    }
}

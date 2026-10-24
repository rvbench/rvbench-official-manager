//! Worker records: durable rows in auth.sqlite plus an in-memory registry that
//! serves the hot paths (token auth, allocate ownership filter, visibility).
//! Heartbeats update memory only; a background task flushes last_seen every 10s
//! (design §4.3) so register traffic never writes the database per poll.
pub mod claim;
pub mod migrate;
pub mod routes;
pub mod store;
pub mod token;

use super::auth::AuthDb;

/// Standalone /claim confirmation page (manager-only; a worker deployment
/// has no owner concept, so it is not part of the protocol crate console).
pub const CLAIM_HTML: &str = include_str!("../../assets/claim.html");
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::RwLock;
use store::WorkerRecord;

#[derive(Default)]
pub struct WorkerRegistry {
    inner: std::sync::Arc<RwLock<BTreeMap<String, WorkerRecord>>>,
}
impl Clone for WorkerRegistry {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}
impl WorkerRegistry {
    pub async fn load(db: &AuthDb, bootstrap: Vec<migrate::BootstrapToken>) -> anyhow::Result<Self> {
        let mut records = db
            .call(|c| {
                store::list_workers(c)
                    .map_err(|e| super::auth::AuthError::internal(e.to_string()))
            })
            .await
            .map_err(|e| anyhow::anyhow!(e.message))?;
        for b in migrate::bootstrap_view(bootstrap) {
            // DB rows win over config bootstrap for the same id.
            if !records.iter().any(|r| r.worker_id == b.worker_id) {
                records.push(b);
            }
        }
        let map = records.into_iter().map(|r| (r.worker_id.clone(), r)).collect();
        Ok(Self {
            inner: std::sync::Arc::new(RwLock::new(map)),
        })
    }
    /// Channel switch (design §2): /cluster/* enforces worker credentials as soon
    /// as any usable token exists, independently of auth.mode.
    pub fn channel_active(&self) -> bool {
        self.inner
            .read()
            .unwrap()
            .values()
            .any(|r| r.status != "revoked")
    }
    pub fn by_token(&self, sha256: &str) -> Option<WorkerRecord> {
        self.inner
            .read()
            .unwrap()
            .values()
            .find(|r| r.token_sha256 == sha256 && r.status != "revoked")
            .cloned()
    }
    pub fn get(&self, worker_id: &str) -> Option<WorkerRecord> {
        self.inner.read().unwrap().get(worker_id).cloned()
    }
    pub fn all(&self) -> Vec<WorkerRecord> {
        self.inner.read().unwrap().values().cloned().collect()
    }
    /// Ownership snapshot for allocate(): worker_id -> (owner_sub, is_public).
    pub fn ownership(&self) -> BTreeMap<String, (String, bool)> {
        self.inner
            .read()
            .unwrap()
            .iter()
            .map(|(id, r)| (id.clone(), (r.owner_sub.clone(), r.is_public())))
            .collect()
    }
    pub fn upsert(&self, record: WorkerRecord) {
        self.inner
            .write()
            .unwrap()
            .insert(record.worker_id.clone(), record);
    }
    pub fn set_last_seen(&self, worker_id: &str, now: f64) {
        if let Some(r) = self.inner.write().unwrap().get_mut(worker_id) {
            r.last_seen = Some(now);
            if r.status == "pending" {
                r.status = "active".into();
            }
        }
    }
    /// Rows whose last_seen moved since the previous flush.
    pub fn drain_dirty(&self, dirty: &mut BTreeMap<String, f64>) -> Vec<(String, f64)> {
        let guard = self.inner.read().unwrap();
        let rows: Vec<_> = dirty
            .iter()
            .filter_map(|(id, t)| guard.get(id).map(|_| (id.clone(), *t)))
            .collect();
        dirty.clear();
        rows
    }
}

/// manager Config.worker_tokens[] bootstrap entries (design §5.3: 64 hex chars).
#[derive(Clone, Serialize, Deserialize)]
pub struct BootstrapWorkerToken {
    pub id: String,
    pub sha256: String,
    #[serde(default)]
    pub created_at: Option<String>,
}

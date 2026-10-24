//! config.worker_tokens[] mapped to read-only bootstrap records (plan W0):
//! owner is always org:rvbench and visibility public; nothing is written to the
//! database, so removing a config entry revokes it on restart.
use super::store::WorkerRecord;

pub struct BootstrapToken {
    pub id: String,
    pub sha256: String,
}
pub fn bootstrap_view(tokens: Vec<BootstrapToken>) -> Vec<WorkerRecord> {
    tokens
        .into_iter()
        .map(|t| WorkerRecord {
            worker_id: t.id,
            owner_sub: "org:rvbench".into(),
            owner_login: "rvbench".into(),
            visibility: "public".into(),
            status: "active".into(),
            token_sha256: t.sha256,
            token_prefix: String::new(),
            created_at: 0.0,
            last_seen: None,
            revoked_at: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_entries_are_public_and_org_owned() {
        let view = bootstrap_view(vec![BootstrapToken {
            id: "k3-1".into(),
            sha256: "a".repeat(64),
        }]);
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].owner_sub, "org:rvbench");
        assert!(view[0].is_public());
        assert_eq!(view[0].status, "active");
    }
}

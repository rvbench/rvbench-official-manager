//! auth_would_deny / auth_denied counters (plan M2, risk #3).
use std::sync::atomic::{AtomicU64, Ordering};
use super::Permission;

pub struct AuthMetrics {
    would_deny: Vec<AtomicU64>,
    denied: AtomicU64,
}
impl Default for AuthMetrics {
    fn default() -> Self {
        Self {
            would_deny: Permission::ALL.iter().map(|_| AtomicU64::new(0)).collect(),
            denied: AtomicU64::new(0),
        }
    }
}
impl AuthMetrics {
    pub fn would_deny(&self, permission: Permission) {
        let i = Permission::ALL.iter().position(|p| *p == permission).unwrap_or(0);
        self.would_deny[i].fetch_add(1, Ordering::Relaxed);
    }
    pub fn denied(&self) {
        self.denied.fetch_add(1, Ordering::Relaxed);
    }
    pub fn render(&self) -> String {
        let mut out = String::from("# TYPE auth_would_deny_total counter\n");
        for (i, p) in Permission::ALL.iter().enumerate() {
            out.push_str(&format!(
                "auth_would_deny_total{{permission=\"{}\"}} {}\n",
                p.as_str(),
                self.would_deny[i].load(Ordering::Relaxed)
            ));
        }
        out.push_str(&format!(
            "# TYPE auth_denied_total counter\nauth_denied_total {}\n",
            self.denied.load(Ordering::Relaxed)
        ));
        out
    }
}

//! workers / worker_claims tables (plan W0/W2). Lives in auth.sqlite next to the
//! session tables; the in-memory WorkerRegistry is the hot path, this is the
//! durable copy. Claim tokens are held in plaintext only until first delivery.
use super::token;
use rusqlite::{Connection, params};
use serde_json::{Value, json};

#[derive(Clone, Debug, Default)]
pub struct WorkerRecord {
    pub worker_id: String,
    pub owner_sub: String,
    pub owner_login: String,
    pub visibility: String, // public | private
    pub status: String,     // pending | active | revoked
    pub token_sha256: String,
    pub token_prefix: String,
    pub created_at: f64,
    pub last_seen: Option<f64>,
    pub revoked_at: Option<f64>,
}
impl WorkerRecord {
    pub fn is_public(&self) -> bool {
        self.visibility == "public"
    }
    pub fn to_json(&self) -> Value {
        json!({
            "worker_id": self.worker_id,
            "owner": {"sub": self.owner_sub, "login": self.owner_login},
            "visibility": self.visibility,
            "status": self.status,
            "token_prefix": self.token_prefix,
            "created_at": crate::auth::iso(self.created_at),
            "last_seen": self.last_seen.map(crate::auth::iso),
            "online": self.last_seen.is_some_and(|t| rvbench_protocol::seconds() - t <= 30.0),
        })
    }
}

pub fn init_tables(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS workers(
          worker_id TEXT PRIMARY KEY, owner_sub TEXT NOT NULL, owner_login TEXT NOT NULL,
          visibility TEXT NOT NULL, status TEXT NOT NULL,
          token_sha256 TEXT NOT NULL, token_prefix TEXT NOT NULL,
          created_at REAL NOT NULL, last_seen REAL, revoked_at REAL);
        CREATE INDEX IF NOT EXISTS workers_token ON workers(token_sha256);
        CREATE TABLE IF NOT EXISTS worker_claims(
          code TEXT PRIMARY KEY, device_code TEXT NOT NULL UNIQUE,
          worker_id TEXT NOT NULL, board_id TEXT NOT NULL, backend TEXT NOT NULL,
          kinds_json TEXT NOT NULL, environment_json TEXT,
          source_ip TEXT, created_at REAL NOT NULL, expires_at REAL NOT NULL,
          status TEXT NOT NULL, approved_by TEXT, approved_at REAL,
          approved_token TEXT, delivered_at REAL);",
    )
}

pub fn list_workers(c: &Connection) -> rusqlite::Result<Vec<WorkerRecord>> {
    let mut stmt = c.prepare(
        "SELECT worker_id,owner_sub,owner_login,visibility,status,token_sha256,token_prefix,created_at,last_seen,revoked_at FROM workers",
    )?;
    let rows = stmt
        .query_map([], record_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
fn record_row(r: &rusqlite::Row) -> rusqlite::Result<WorkerRecord> {
    Ok(WorkerRecord {
        worker_id: r.get(0)?,
        owner_sub: r.get(1)?,
        owner_login: r.get(2)?,
        visibility: r.get(3)?,
        status: r.get(4)?,
        token_sha256: r.get(5)?,
        token_prefix: r.get(6)?,
        created_at: r.get(7)?,
        last_seen: r.get(8)?,
        revoked_at: r.get(9)?,
    })
}
pub fn insert_worker(c: &Connection, w: &WorkerRecord) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO workers(worker_id,owner_sub,owner_login,visibility,status,token_sha256,token_prefix,created_at,last_seen)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL)",
        params![w.worker_id, w.owner_sub, w.owner_login, w.visibility, w.status, w.token_sha256, w.token_prefix, w.created_at],
    )?;
    Ok(())
}
pub fn rotate_token(
    c: &Connection,
    worker_id: &str,
    sha: &str,
    prefix: &str,
    now: f64,
) -> rusqlite::Result<bool> {
    Ok(c.execute(
        "UPDATE workers SET token_sha256=?2, token_prefix=?3, status=CASE WHEN status='revoked' THEN 'revoked' ELSE 'active' END, created_at=?4 WHERE worker_id=?1",
        params![worker_id, sha, prefix, now],
    )? > 0)
}
pub fn revoke_worker(c: &Connection, worker_id: &str, now: f64) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE workers SET status='revoked', revoked_at=?2 WHERE worker_id=?1",
        params![worker_id, now],
    )?;
    Ok(())
}
pub fn mark_active(c: &Connection, worker_id: &str, now: f64) -> rusqlite::Result<()> {
    c.execute(
        "UPDATE workers SET status='active', last_seen=?2 WHERE worker_id=?1",
        params![worker_id, now],
    )?;
    Ok(())
}
pub fn flush_last_seen(c: &Connection, rows: &[(String, f64)]) -> rusqlite::Result<()> {
    let mut stmt = c.prepare("UPDATE workers SET last_seen=?2 WHERE worker_id=?1")?;
    for (id, t) in rows {
        stmt.execute(params![id, t])?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ClaimRow {
    pub code: String,
    pub device_code: String,
    pub worker_id: String,
    pub board_id: String,
    pub backend: String,
    pub kinds: Vec<String>,
    pub environment: Option<Value>,
    pub source_ip: Option<String>,
    pub created_at: f64,
    pub expires_at: f64,
    pub status: String,
    pub approved_token: Option<String>,
    pub delivered_at: Option<f64>,
}
impl ClaimRow {
    pub fn to_view(&self) -> Value {
        json!({
            "code": self.code, "worker_id": self.worker_id, "board_id": self.board_id,
            "backend": self.backend, "kinds": self.kinds, "source_ip": self.source_ip,
            "requested_at": crate::auth::iso(self.created_at),
            "expires_at": crate::auth::iso(self.expires_at),
            "status": self.status,
        })
    }
}
pub fn insert_claim(c: &Connection, k: &ClaimRow) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO worker_claims(code,device_code,worker_id,board_id,backend,kinds_json,environment_json,source_ip,created_at,expires_at,status)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'pending')",
        params![k.code, k.device_code, k.worker_id, k.board_id, k.backend,
                serde_json::to_string(&k.kinds).unwrap(), 
                k.environment.as_ref().map(|v| serde_json::to_string(v).unwrap()),
                k.source_ip, k.created_at, k.expires_at],
    )?;
    Ok(())
}
pub fn get_claim_by_code(c: &Connection, code: &str) -> rusqlite::Result<Option<ClaimRow>> {
    c.query_row("SELECT * FROM worker_claims WHERE code=?1", params![code], claim_row)
        .map(Some)
        .or_else(no_rows)
}
pub fn get_claim_by_device(c: &Connection, device_code: &str) -> rusqlite::Result<Option<ClaimRow>> {
    c.query_row(
        "SELECT * FROM worker_claims WHERE device_code=?1",
        params![device_code],
        claim_row,
    )
    .map(Some)
    .or_else(no_rows)
}
pub fn list_pending_claims(c: &Connection, now: f64) -> rusqlite::Result<Vec<ClaimRow>> {
    let mut stmt =
        c.prepare("SELECT * FROM worker_claims WHERE status='pending' AND expires_at > ?1 ORDER BY created_at")?;
    let rows = stmt.query_map(params![now], claim_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
/// One-shot transition guarded by status; 0 affected rows means someone else won.
pub fn decide_claim(
    c: &Connection,
    code: &str,
    new_status: &str,
    approved_by: Option<&str>,
    token: Option<&str>,
    now: f64,
) -> rusqlite::Result<bool> {
    let changed = c.execute(
        "UPDATE worker_claims SET status=?2, approved_by=?3, approved_at=?4, approved_token=?5
         WHERE code=?1 AND status='pending'",
        params![code, new_status, approved_by, now, token],
    )?;
    Ok(changed > 0)
}
pub fn take_claim_token(c: &Connection, code: &str, now: f64) -> rusqlite::Result<Option<String>> {
    let row = c
        .query_row(
            "SELECT approved_token FROM worker_claims WHERE code=?1 AND status='approved' AND delivered_at IS NULL",
            params![code],
            |r| r.get::<_, Option<String>>(0),
        )
        .map(Some)
        .or_else(no_rows)?;
    if row.is_some() {
        c.execute(
            "UPDATE worker_claims SET approved_token=NULL, delivered_at=?2 WHERE code=?1",
            params![code, now],
        )?;
    }
    Ok(row.flatten())
}
pub fn expire_claims(c: &Connection, now: f64) -> rusqlite::Result<usize> {
    Ok(c.execute(
        "UPDATE worker_claims SET status='expired' WHERE status='pending' AND expires_at < ?1",
        params![now],
    )?)
}
pub fn cleanup_claims(c: &Connection, now: f64) -> rusqlite::Result<usize> {
    Ok(c.execute(
        "DELETE FROM worker_claims WHERE expires_at < ?1 - 86400.0",
        params![now],
    )?)
}
fn claim_row(r: &rusqlite::Row) -> rusqlite::Result<ClaimRow> {
    let kinds: String = r.get("kinds_json")?;
    let env: Option<String> = r.get("environment_json")?;
    Ok(ClaimRow {
        code: r.get("code")?,
        device_code: r.get("device_code")?,
        worker_id: r.get("worker_id")?,
        board_id: r.get("board_id")?,
        backend: r.get("backend")?,
        kinds: serde_json::from_str(&kinds).unwrap_or_default(),
        environment: env.and_then(|e| serde_json::from_str(&e).ok()),
        source_ip: r.get("source_ip")?,
        created_at: r.get("created_at")?,
        expires_at: r.get("expires_at")?,
        status: r.get("status")?,
        approved_token: r.get("approved_token")?,
        delivered_at: r.get("delivered_at")?,
    })
}
fn no_rows<T>(e: rusqlite::Error) -> Result<Option<T>, rusqlite::Error> {
    match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        e => Err(e),
    }
}

pub fn worker_id_taken(c: &Connection, worker_id: &str) -> rusqlite::Result<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM workers WHERE worker_id=?1 AND status != 'revoked'",
        params![worker_id],
        |_| Ok(()),
    )
    .is_ok())
}

/// Token helper re-export so routes can mint without importing two modules.
pub fn new_token() -> (String, String, String) {
    let t = token::generate();
    (t.clone(), token::sha256_hex(&t), token::prefix(&t))
}

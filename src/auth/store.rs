//! auth.sqlite: principals / sessions / role_cache / login_states / audit (design D9).
//! Kept separate from the ManagerData snapshot; WAL + NORMAL sync is enough for auth rows.
use super::error::AuthError;
use super::provider::ProviderUser;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{path::Path, sync::{Arc, Mutex}};

#[derive(Clone)]
pub struct AuthDb {
    connection: Arc<Mutex<Connection>>,
}
impl AuthDb {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let c = Connection::open(path)?;
        Self::init(c).map_err(anyhow::Error::from)
    }
    /// Volatile auth state for `auth.mode = off` (nothing is ever written).
    pub fn memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?).map_err(anyhow::Error::from)
    }
    fn init(c: Connection) -> Result<Self, rusqlite::Error> {
        c.busy_timeout(std::time::Duration::from_secs(5))?;
        // role_cache.degraded extends D9: a degraded entry is re-probed after 60s.
        // sessions.provider_token enables the D3 mid-session role refresh; never
        // returned by any endpoint and never logged.
        c.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS principals(
              sub TEXT PRIMARY KEY, provider TEXT NOT NULL, login TEXT NOT NULL,
              name TEXT, email TEXT, avatar_url TEXT,
              first_seen REAL NOT NULL, last_seen REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS principals_login ON principals(login);
            CREATE TABLE IF NOT EXISTS sessions(
              token_sha256 TEXT PRIMARY KEY, sub TEXT NOT NULL, kind TEXT NOT NULL,
              created_at REAL NOT NULL, expires_at REAL NOT NULL, last_seen REAL NOT NULL,
              revoked_at REAL, user_agent TEXT, ip TEXT, provider_token TEXT);
            CREATE INDEX IF NOT EXISTS sessions_sub ON sessions(sub);
            CREATE TABLE IF NOT EXISTS role_cache(
              sub TEXT PRIMARY KEY, is_early_access INTEGER NOT NULL,
              degraded INTEGER NOT NULL DEFAULT 0,
              checked_at REAL NOT NULL, expires_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS login_states(
              state TEXT PRIMARY KEY, kind TEXT NOT NULL, pkce_verifier TEXT,
              redirect_after TEXT, created_at REAL NOT NULL, expires_at REAL NOT NULL,
              consumed_at REAL);
            CREATE TABLE IF NOT EXISTS audit(
              id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, sub TEXT, login TEXT,
              action TEXT NOT NULL, target TEXT, result TEXT NOT NULL, ip TEXT, detail TEXT);
            CREATE INDEX IF NOT EXISTS audit_at ON audit(at);",
        )?;
        Ok(Self { connection: Arc::new(Mutex::new(c)) })
    }
    pub async fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> Result<R, AuthError> + Send + 'static,
    ) -> Result<R, AuthError> {
        let connection = self.connection.clone();
        tokio::task::spawn_blocking(move || {
            let c = connection
                .lock()
                .map_err(|_| AuthError::internal("database poisoned"))?;
            f(&c)
        })
        .await
        .map_err(|e| AuthError::internal(e))?
    }
    /// Drops login states an hour past expiry; run at startup and hourly (design D9).
    pub fn cleanup_sync(&self, now: f64) -> usize {
        self.connection
            .lock()
            .map(|c| {
                c.execute("DELETE FROM login_states WHERE expires_at < ?1", params![now - 3600.0])
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }
}

#[derive(Clone, Debug)]
pub struct PrincipalRow {
    pub sub: String,
    pub provider: String,
    pub login: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}
#[derive(Clone, Debug)]
pub struct SessionRow {
    pub token_sha256: String,
    pub sub: String,
    pub kind: String,
    pub created_at: f64,
    pub expires_at: f64,
    pub last_seen: f64,
    pub revoked_at: Option<f64>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub provider_token: Option<String>,
}
impl SessionRow {
    pub fn id16(&self) -> String {
        self.token_sha256.chars().take(16).collect()
    }
}

pub fn upsert_principal(
    c: &Connection,
    user: &ProviderUser,
    provider: &str,
    now: f64,
) -> Result<PrincipalRow, AuthError> {
    c.execute(
        "INSERT INTO principals(sub,provider,login,name,email,avatar_url,first_seen,last_seen)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?7)
         ON CONFLICT(sub) DO UPDATE SET login=?3,name=?4,email=?5,avatar_url=?6,provider=?2,last_seen=?7",
        params![user.sub, provider, user.login, user.name, user.email, user.avatar_url, now],
    )?;
    get_principal(c, &user.sub)?.ok_or_else(|| AuthError::internal("principal upsert lost the row"))
}
pub fn get_principal(c: &Connection, sub: &str) -> Result<Option<PrincipalRow>, AuthError> {
    let mut stmt = c.prepare(
        "SELECT sub,provider,login,name,email,avatar_url FROM principals WHERE sub=?1",
    )?;
    let row = stmt
        .query_row(params![sub], |r| {
            Ok(PrincipalRow {
                sub: r.get(0)?,
                provider: r.get(1)?,
                login: r.get(2)?,
                name: r.get(3)?,
                email: r.get(4)?,
                avatar_url: r.get(5)?,
            })
        })
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    Ok(row)
}
pub fn insert_session(
    c: &Connection,
    token_sha256: &str,
    sub: &str,
    kind: &str,
    ttl: f64,
    user_agent: Option<&str>,
    ip: Option<&str>,
    provider_token: Option<&str>,
    now: f64,
) -> Result<f64, AuthError> {
    let expires = now + ttl;
    c.execute(
        "INSERT INTO sessions(token_sha256,sub,kind,created_at,expires_at,last_seen,user_agent,ip,provider_token)
         VALUES(?1,?2,?3,?4,?5,?4,?6,?7,?8)",
        params![token_sha256, sub, kind, now, expires, user_agent, ip, provider_token],
    )?;
    Ok(expires)
}
pub fn find_session(c: &Connection, sha: &str, now: f64) -> Result<Option<SessionRow>, AuthError> {
    let session = c
        .query_row("SELECT * FROM sessions WHERE token_sha256=?1", params![sha], session_row)
        .map(Some)
        .or_else(no_rows)?;
    Ok(session.filter(|s| s.revoked_at.is_none() && s.expires_at > now))
}
pub fn session_by_id(c: &Connection, id16: &str) -> Result<Option<SessionRow>, AuthError> {
    c.query_row(
        "SELECT * FROM sessions WHERE substr(token_sha256,1,16)=?1",
        params![id16],
        session_row,
    )
    .map(Some)
    .or_else(no_rows)
}
/// Slides a web session when less than half its TTL remains; always refreshes last_seen.
pub fn touch_session(
    c: &Connection,
    sha: &str,
    now: f64,
    ttl: f64,
) -> Result<Option<f64>, AuthError> {
    let Some(s) = find_session(c, sha, now)? else { return Ok(None) };
    if s.kind == "web" && s.expires_at - now < ttl / 2.0 {
        let expires = now + ttl;
        c.execute(
            "UPDATE sessions SET last_seen=?1, expires_at=?2 WHERE token_sha256=?3",
            params![now, expires, sha],
        )?;
        Ok(Some(expires))
    } else {
        c.execute(
            "UPDATE sessions SET last_seen=?1 WHERE token_sha256=?2",
            params![now, sha],
        )?;
        Ok(None)
    }
}
pub fn revoke_by_sha(c: &Connection, sha: &str, now: f64) -> Result<bool, AuthError> {
    Ok(c.execute(
        "UPDATE sessions SET revoked_at=?1 WHERE token_sha256=?2 AND revoked_at IS NULL",
        params![now, sha],
    )? > 0)
}
pub fn revoke_by_id(c: &Connection, id16: &str, now: f64) -> Result<Option<SessionRow>, AuthError> {
    let Some(s) = session_by_id(c, id16)? else { return Ok(None) };
    if s.revoked_at.is_none() {
        c.execute(
            "UPDATE sessions SET revoked_at=?1 WHERE token_sha256=?2",
            params![now, &s.token_sha256],
        )?;
    }
    Ok(Some(s))
}
pub fn list_sessions(c: &Connection, sub: &str) -> Result<Vec<SessionRow>, AuthError> {
    let mut stmt = c.prepare(
        "SELECT * FROM sessions WHERE sub=?1 ORDER BY created_at DESC LIMIT 50",
    )?;
    let rows = stmt
        .query_map(params![sub], session_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
fn session_row(r: &rusqlite::Row) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        token_sha256: r.get("token_sha256")?,
        sub: r.get("sub")?,
        kind: r.get("kind")?,
        created_at: r.get("created_at")?,
        expires_at: r.get("expires_at")?,
        last_seen: r.get("last_seen")?,
        revoked_at: r.get("revoked_at")?,
        user_agent: r.get("user_agent")?,
        ip: r.get("ip")?,
        provider_token: r.get("provider_token")?,
    })
}
fn no_rows<R>(e: rusqlite::Error) -> Result<Option<R>, AuthError> {
    match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        e => Err(e.into()),
    }
}

pub fn cache_get(c: &Connection, sub: &str, now: f64) -> Result<Option<(bool, bool)>, AuthError> {
    c.query_row(
        "SELECT is_early_access,degraded FROM role_cache WHERE sub=?1 AND expires_at > ?2",
        params![sub, now],
        |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, i64>(1)? != 0)),
    )
    .map(Some)
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        e => Err(e.into()),
    })
}
pub fn cache_put(
    c: &Connection,
    sub: &str,
    early: bool,
    degraded: bool,
    now: f64,
    ttl: f64,
) -> Result<(), AuthError> {
    c.execute(
        "INSERT INTO role_cache(sub,is_early_access,degraded,checked_at,expires_at)
         VALUES(?1,?2,?3,?4,?5)
         ON CONFLICT(sub) DO UPDATE SET is_early_access=?2,degraded=?3,checked_at=?4,expires_at=?5",
        params![sub, early as i64, degraded as i64, now, now + ttl],
    )?;
    Ok(())
}

pub fn state_insert(
    c: &Connection,
    state: &str,
    verifier: &str,
    redirect: &str,
    now: f64,
    ttl: f64,
) -> Result<(), AuthError> {
    c.execute(
        "INSERT INTO login_states(state,kind,pkce_verifier,redirect_after,created_at,expires_at)
         VALUES(?1,'web',?2,?3,?4,?5)",
        params![state, verifier, redirect, now, now + ttl],
    )?;
    Ok(())
}
/// One-time consume: only an unconsumed, unexpired state resolves (design §4.1).
pub fn state_consume(c: &Connection, state: &str, now: f64) -> Result<Option<(String, String)>, AuthError> {
    let row = c
        .query_row(
            "SELECT pkce_verifier,redirect_after FROM login_states
             WHERE state=?1 AND consumed_at IS NULL AND expires_at > ?2",
            params![state, now],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .map(Some)
        .or_else(no_rows)?;
    if row.is_some() {
        c.execute(
            "UPDATE login_states SET consumed_at=?1 WHERE state=?2",
            params![now, state],
        )?;
    }
    Ok(row)
}

pub fn audit_append(
    c: &Connection,
    now: f64,
    sub: Option<&str>,
    login: Option<&str>,
    action: &str,
    target: Option<&str>,
    result: &str,
    ip: Option<&str>,
    detail: Option<&str>,
) -> Result<(), AuthError> {
    c.execute(
        "INSERT INTO audit(at,sub,login,action,target,result,ip,detail) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![now, sub, login, action, target, result, ip, detail],
    )?;
    Ok(())
}
pub fn audit_query(
    c: &Connection,
    sub: Option<&str>,
    action: Option<&str>,
    since: Option<f64>,
    limit: u32,
) -> Result<Vec<Value>, AuthError> {
    let mut sql = "SELECT id,at,sub,login,action,target,result,ip,detail FROM audit WHERE 1=1".to_string();
    let mut args = Vec::<Box<dyn rusqlite::ToSql>>::new();
    if let Some(s) = sub {
        args.push(Box::new(s.to_string()));
        sql.push_str(&format!(" AND sub=?{}", args.len()));
    }
    if let Some(a) = action {
        args.push(Box::new(a.to_string()));
        sql.push_str(&format!(" AND action=?{}", args.len()));
    }
    if let Some(t) = since {
        args.push(Box::new(t));
        sql.push_str(&format!(" AND at>?{}", args.len()));
    }
    args.push(Box::new(limit));
    sql.push_str(&format!(" ORDER BY id DESC LIMIT ?{}", args.len()));
    let mut stmt = c.prepare(&sql)?;
    let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
    let rows = stmt
        .query_map(refs.as_slice(), |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "at": crate::auth::iso(r.get::<_, f64>(1)?),
                "sub": r.get::<_, Option<String>>(2)?,
                "login": r.get::<_, Option<String>>(3)?,
                "action": r.get::<_, String>(4)?,
                "target": r.get::<_, Option<String>>(5)?,
                "result": r.get::<_, String>(6)?,
                "ip": r.get::<_, Option<String>>(7)?,
                "detail": r.get::<_, Option<String>>(8)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn db() -> (tempfile::TempDir, AuthDb) {
        let t = tempfile::tempdir().unwrap();
        let d = AuthDb::open(&t.path().join("auth.sqlite")).unwrap();
        (t, d)
    }
    #[tokio::test]
    async fn session_lifecycle_from_insert_to_revocation() {
        let (_t, d) = db();
        let now = rvbench_protocol::seconds();
        let user = ProviderUser { sub: "github:1".into(), login: "alice".into(), name: None, email: None, avatar_url: None };
        d.call(move |c| {
            upsert_principal(c, &user, "static", now)?;
            insert_session(c, "aa", "github:1", "web", 3600.0, Some("ua"), Some("ip"), None, now)
        })
        .await
        .unwrap();
        let found = d.call(move |c| find_session(c, "aa", rvbench_protocol::seconds())).await.unwrap();
        assert!(found.is_some());
        // Expired sessions are invisible.
        d.call(move |c| {
            c.execute("UPDATE sessions SET expires_at=1", [])?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(d.call(move |c| find_session(c, "aa", 2.0)).await.unwrap().is_none());
        // Sliding renewal fires only in the last half of the TTL.
        d.call(move |c| {
            c.execute("UPDATE sessions SET expires_at=?1, revoked_at=NULL", params![rvbench_protocol::seconds() + 100.0])?;
            Ok(())
        })
        .await
        .unwrap();
        let renewed = d
            .call(move |c| touch_session(c, "aa", rvbench_protocol::seconds(), 3600.0))
            .await
            .unwrap();
        assert!(renewed.is_some(), "web session in its last half must slide");
        assert!(d.call(move |c| revoke_by_sha(c, "aa", 99.0)).await.unwrap());
        assert!(d.call(move |c| find_session(c, "aa", rvbench_protocol::seconds())).await.unwrap().is_none());
    }
    #[tokio::test]
    async fn login_state_is_single_use() {
        let (_t, d) = db();
        d.call(move |c| state_insert(c, "s1", "verifier", "/ui", 100.0, 600.0)).await.unwrap();
        let first = d.call(move |c| state_consume(c, "s1", 200.0)).await.unwrap();
        assert_eq!(first.unwrap(), ("verifier".into(), "/ui".into()));
        assert!(d.call(move |c| state_consume(c, "s1", 300.0)).await.unwrap().is_none());
        // Expired state never resolves even when unconsumed.
        d.call(move |c| state_insert(c, "s2", "v", "/ui", 100.0, 50.0)).await.unwrap();
        assert!(d.call(move |c| state_consume(c, "s2", 200.0)).await.unwrap().is_none());
    }
    #[tokio::test]
    async fn audit_roundtrip_with_filters() {
        let (_t, d) = db();
        d.call(move |c| {
            audit_append(c, 1.0, Some("github:1"), Some("alice"), "login", None, "ok", None, None)?;
            audit_append(c, 2.0, Some("github:2"), Some("bob"), "job.submit", Some("j1"), "ok", None, None)?;
            audit_append(c, 3.0, None, None, "login_failed", None, "denied", Some("1.2.3.4"), None)
        })
        .await
        .unwrap();
        let all = d.call(|c| audit_query(c, None, None, None, 100)).await.unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0]["action"], "login_failed");
        let logins = d.call(|c| audit_query(c, None, Some("login"), None, 100)).await.unwrap();
        assert_eq!(logins.len(), 1);
        let recent = d.call(|c| audit_query(c, None, None, Some(1.5), 100)).await.unwrap();
        assert_eq!(recent.len(), 2);
    }
}

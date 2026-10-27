//! auth.sqlite: principals / sessions / role_cache / login_states / audit (design D9).
//! Kept separate from the ManagerData snapshot; WAL + NORMAL sync is enough for auth rows.
use super::error::AuthError;
use super::provider::ProviderUser;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

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
        // returned by any endpoint and never logged. label / deleted_at / role_grants
        // also exist as migrations below, but a fresh database gets the full schema
        // from this batch so the chain only has work to do on old files.
        c.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS principals(
              sub TEXT PRIMARY KEY, provider TEXT NOT NULL, login TEXT NOT NULL,
              name TEXT, email TEXT, avatar_url TEXT,
              first_seen REAL NOT NULL, last_seen REAL NOT NULL, deleted_at REAL);
            CREATE INDEX IF NOT EXISTS principals_login ON principals(login);
            CREATE TABLE IF NOT EXISTS sessions(
              token_sha256 TEXT PRIMARY KEY, sub TEXT NOT NULL, kind TEXT NOT NULL,
              created_at REAL NOT NULL, expires_at REAL NOT NULL, last_seen REAL NOT NULL,
              revoked_at REAL, user_agent TEXT, ip TEXT, provider_token TEXT, label TEXT);
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
            CREATE INDEX IF NOT EXISTS audit_at ON audit(at);
            CREATE TABLE IF NOT EXISTS role_grants(
              sub TEXT NOT NULL, role TEXT NOT NULL, granted_by TEXT NOT NULL,
              granted_at REAL NOT NULL, revoked_at REAL, PRIMARY KEY(sub, role));
            CREATE INDEX IF NOT EXISTS role_grants_sub ON role_grants(sub);",
        )?;
        migrate(&c)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(c)),
        })
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
                c.execute(
                    "DELETE FROM login_states WHERE expires_at < ?1",
                    params![now - 3600.0],
                )
                .unwrap_or(0)
            })
            .unwrap_or(0)
    }
}

/// Versioned migrations over `PRAGMA user_version`. Each step is idempotent and a
/// failure never advances the version, so an older binary can still open the file
/// (old code ignores the new columns/tables entirely).
fn migrate(c: &Connection) -> Result<(), rusqlite::Error> {
    let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    // Probing table_info instead of swallowing `duplicate column` errors keeps a
    // half-applied step (crash between ALTER and the version bump) recoverable:
    // the next open skips the applied ALTER and finishes the chain.
    if version < 1 {
        if !has_column(c, "sessions", "label")? {
            c.execute("ALTER TABLE sessions ADD COLUMN label TEXT", [])?;
        }
        c.execute_batch("PRAGMA user_version=1;")?;
    }
    if version < 2 {
        if !has_column(c, "principals", "deleted_at")? {
            c.execute("ALTER TABLE principals ADD COLUMN deleted_at REAL", [])?;
        }
        c.execute_batch("PRAGMA user_version=2;")?;
    }
    if version < 3 {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS role_grants(
               sub TEXT NOT NULL, role TEXT NOT NULL, granted_by TEXT NOT NULL,
               granted_at REAL NOT NULL, revoked_at REAL, PRIMARY KEY(sub, role));
             CREATE INDEX IF NOT EXISTS role_grants_sub ON role_grants(sub);",
        )?;
        c.execute_batch("PRAGMA user_version=3;")?;
    }
    Ok(())
}
fn has_column(c: &Connection, table: &str, column: &str) -> Result<bool, rusqlite::Error> {
    let mut stmt = c.prepare("SELECT 1 FROM pragma_table_info(?1) WHERE name=?2")?;
    let mut rows = stmt.query(params![table, column])?;
    Ok(rows.next()?.is_some())
}

#[derive(Clone, Debug)]
pub struct PrincipalRow {
    pub sub: String,
    pub provider: String,
    pub login: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub first_seen: f64,
    pub last_seen: f64,
    pub deleted_at: Option<f64>,
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
    pub label: Option<String>,
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
        "SELECT sub,provider,login,name,email,avatar_url,first_seen,last_seen,deleted_at
         FROM principals WHERE sub=?1",
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
                first_seen: r.get(6)?,
                last_seen: r.get(7)?,
                deleted_at: r.get(8)?,
            })
        })
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    Ok(row)
}
/// M3 account deletion is a tombstone, not a row delete: sub survives for audit and
/// task attribution while the identity fields are irreversibly scrubbed. Re-running
/// on an already-tombstoned row just repeats the same scrub, never errors.
pub fn tombstone_principal(
    c: &Connection,
    sub: &str,
    now: f64,
) -> Result<Option<PrincipalRow>, AuthError> {
    let Some(p) = get_principal(c, sub)? else {
        return Ok(None);
    };
    // `deleted-<sha8 of the old login>` keeps the audit trail linkable (plan §9)
    // without keeping the login itself.
    let login = format!("deleted-{}", &super::session::sha256_hex(&p.login)[..8]);
    c.execute(
        "UPDATE principals SET login=?1,name=NULL,email=NULL,avatar_url=NULL,deleted_at=?2
         WHERE sub=?3",
        params![login, now, sub],
    )?;
    c.execute(
        "UPDATE sessions SET revoked_at=?1 WHERE sub=?2 AND revoked_at IS NULL",
        params![now, sub],
    )?;
    cache_delete(c, sub)?;
    get_principal(c, sub)?
        .ok_or_else(|| AuthError::internal("tombstone lost the row"))
        .map(Some)
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
        .query_row(
            "SELECT * FROM sessions WHERE token_sha256=?1",
            params![sha],
            session_row,
        )
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
    let Some(s) = find_session(c, sha, now)? else {
        return Ok(None);
    };
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
    let Some(s) = session_by_id(c, id16)? else {
        return Ok(None);
    };
    if s.revoked_at.is_none() {
        c.execute(
            "UPDATE sessions SET revoked_at=?1 WHERE token_sha256=?2",
            params![now, &s.token_sha256],
        )?;
    }
    Ok(Some(s))
}
pub fn list_sessions(c: &Connection, sub: &str) -> Result<Vec<SessionRow>, AuthError> {
    let mut stmt =
        c.prepare("SELECT * FROM sessions WHERE sub=?1 ORDER BY created_at DESC LIMIT 50")?;
    let rows = stmt
        .query_map(params![sub], session_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
/// Names a session/token for the credential list (M2). Kept separate from
/// `insert_session` so its signature and existing call sites stay untouched.
pub fn set_session_label(c: &Connection, sha: &str, label: Option<&str>) -> Result<(), AuthError> {
    c.execute(
        "UPDATE sessions SET label=?1 WHERE token_sha256=?2",
        params![label, sha],
    )?;
    Ok(())
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
        label: r.get("label")?,
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
/// Drops a sub's cached GitHub probe so the next request re-derives roles; this is
/// what makes a role PATCH take effect without waiting out the cache TTL.
pub fn cache_delete(c: &Connection, sub: &str) -> Result<(), AuthError> {
    c.execute("DELETE FROM role_cache WHERE sub=?1", params![sub])?;
    Ok(())
}

// --- M4 DB role grants: config.auth.admins stays as the bootstrap list; these rows
// are the runtime-adjustable overlay that role::derive stacks on top of it. ---

/// Active (unrevoked) DB grants for a sub, ordered for stable assertions/output.
pub fn grants_for(c: &Connection, sub: &str) -> Result<Vec<String>, AuthError> {
    let mut stmt = c.prepare(
        "SELECT role FROM role_grants WHERE sub=?1 AND revoked_at IS NULL ORDER BY role",
    )?;
    let roles = stmt
        .query_map(params![sub], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(roles)
}
/// UPSERT semantics: re-granting a revoked role clears `revoked_at` and restamps
/// granted_by/granted_at, so a grant/revoke/grant cycle ends fully active.
pub fn grant_roles(
    c: &Connection,
    sub: &str,
    roles: &[&str],
    granted_by: &str,
    now: f64,
) -> Result<(), AuthError> {
    for role in roles {
        c.execute(
            "INSERT INTO role_grants(sub,role,granted_by,granted_at,revoked_at)
             VALUES(?1,?2,?3,?4,NULL)
             ON CONFLICT(sub,role) DO UPDATE SET granted_by=?3,granted_at=?4,revoked_at=NULL",
            params![sub, role, granted_by, now],
        )?;
    }
    Ok(())
}
pub fn revoke_roles(c: &Connection, sub: &str, roles: &[&str], now: f64) -> Result<(), AuthError> {
    for role in roles {
        // Guarded on revoked_at IS NULL so a repeat revoke keeps the original
        // timestamp instead of restamping it; missing rows are simply a no-op.
        c.execute(
            "UPDATE role_grants SET revoked_at=?3 WHERE sub=?1 AND role=?2 AND revoked_at IS NULL",
            params![sub, role, now],
        )?;
    }
    Ok(())
}
/// All subs holding an active admin DB grant; used by the last-admin guard, which
/// must also see grants the config list cannot provide.
pub fn admin_grant_subs(c: &Connection) -> Result<Vec<String>, AuthError> {
    let mut stmt = c.prepare(
        "SELECT DISTINCT sub FROM role_grants WHERE role='admin' AND revoked_at IS NULL",
    )?;
    let subs = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(subs)
}

/// One row of the admin console user listing (M4).
pub struct UserRow {
    pub sub: String,
    pub login: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub first_seen: f64,
    pub last_seen: f64,
    pub deleted_at: Option<f64>,
    /// Active DB grants only. Admins coming from `config.admins` are not rows in
    /// this database; the caller merges that static list on top.
    pub db_roles: Vec<String>,
}
/// Console listing ordered by first_seen DESC. `q` is a substring match on
/// login/name with LIKE wildcards taken literally (ESCAPE '\'). `role` filters on
/// DB grants — "admin" / "early_access" — where early_access also credits a
/// role_cache probe (degraded rows included: they are refreshed within minutes
/// anyway and there is no `now` here to cut on expiry); any other value is no
/// filter. Returns `(rows, has_more)` by fetching limit+1 rows.
pub fn list_users(
    c: &Connection,
    q: Option<&str>,
    role: Option<&str>,
    limit: u32,
    offset: u32,
) -> Result<(Vec<UserRow>, bool), AuthError> {
    let mut sql = "SELECT sub,login,name,email,avatar_url,first_seen,last_seen,deleted_at
                   FROM principals WHERE 1=1"
        .to_string();
    let mut args = Vec::<Box<dyn rusqlite::ToSql>>::new();
    if let Some(q) = q {
        let pattern = format!("%{}%", like_escape(q));
        sql.push_str(&format!(
            " AND (login LIKE ?{} ESCAPE '\\' OR name LIKE ?{} ESCAPE '\\')",
            args.len() + 1,
            args.len() + 2
        ));
        args.push(Box::new(pattern.clone()));
        args.push(Box::new(pattern));
    }
    match role {
        Some("admin") => sql.push_str(
            " AND EXISTS(SELECT 1 FROM role_grants rg
               WHERE rg.sub=principals.sub AND rg.role='admin' AND rg.revoked_at IS NULL)",
        ),
        Some("early_access") => sql.push_str(
            " AND (EXISTS(SELECT 1 FROM role_grants rg
                 WHERE rg.sub=principals.sub AND rg.role='early_access' AND rg.revoked_at IS NULL)
               OR EXISTS(SELECT 1 FROM role_cache rc
                 WHERE rc.sub=principals.sub AND rc.is_early_access=1))",
        ),
        _ => {}
    }
    // sub tiebreaker keeps pages stable when rows share a first_seen timestamp.
    sql.push_str(" ORDER BY first_seen DESC, sub ASC");
    args.push(Box::new(limit + 1));
    sql.push_str(&format!(" LIMIT ?{}", args.len()));
    args.push(Box::new(offset));
    sql.push_str(&format!(" OFFSET ?{}", args.len()));
    let mut stmt = c.prepare(&sql)?;
    let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
    let mut users = stmt
        .query_map(refs.as_slice(), |r| {
            Ok(UserRow {
                sub: r.get(0)?,
                login: r.get(1)?,
                name: r.get(2)?,
                email: r.get(3)?,
                avatar_url: r.get(4)?,
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
                deleted_at: r.get(7)?,
                db_roles: Vec::new(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let has_more = users.len() as u32 > limit;
    users.truncate(limit as usize);
    // Page sizes are small; one prepared lookup per row beats a group_concat join.
    let mut grants = c.prepare(
        "SELECT role FROM role_grants WHERE sub=?1 AND revoked_at IS NULL ORDER BY role",
    )?;
    for u in &mut users {
        u.db_roles = grants
            .query_map(params![u.sub], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
    }
    Ok((users, has_more))
}
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
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
pub fn state_consume(
    c: &Connection,
    state: &str,
    now: f64,
) -> Result<Option<(String, String)>, AuthError> {
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
    let mut sql =
        "SELECT id,at,sub,login,action,target,result,ip,detail FROM audit WHERE 1=1".to_string();
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
        let user = ProviderUser {
            sub: "github:1".into(),
            login: "alice".into(),
            name: None,
            email: None,
            avatar_url: None,
        };
        d.call(move |c| {
            upsert_principal(c, &user, "static", now)?;
            insert_session(
                c,
                "aa",
                "github:1",
                "web",
                3600.0,
                Some("ua"),
                Some("ip"),
                None,
                now,
            )
        })
        .await
        .unwrap();
        let found = d
            .call(move |c| find_session(c, "aa", rvbench_protocol::seconds()))
            .await
            .unwrap();
        assert!(found.is_some());
        // Expired sessions are invisible.
        d.call(move |c| {
            c.execute("UPDATE sessions SET expires_at=1", [])?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            d.call(move |c| find_session(c, "aa", 2.0))
                .await
                .unwrap()
                .is_none()
        );
        // Sliding renewal fires only in the last half of the TTL.
        d.call(move |c| {
            c.execute(
                "UPDATE sessions SET expires_at=?1, revoked_at=NULL",
                params![rvbench_protocol::seconds() + 100.0],
            )?;
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
        assert!(
            d.call(move |c| find_session(c, "aa", rvbench_protocol::seconds()))
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn login_state_is_single_use() {
        let (_t, d) = db();
        d.call(move |c| state_insert(c, "s1", "verifier", "/ui", 100.0, 600.0))
            .await
            .unwrap();
        let first = d
            .call(move |c| state_consume(c, "s1", 200.0))
            .await
            .unwrap();
        assert_eq!(first.unwrap(), ("verifier".into(), "/ui".into()));
        assert!(
            d.call(move |c| state_consume(c, "s1", 300.0))
                .await
                .unwrap()
                .is_none()
        );
        // Expired state never resolves even when unconsumed.
        d.call(move |c| state_insert(c, "s2", "v", "/ui", 100.0, 50.0))
            .await
            .unwrap();
        assert!(
            d.call(move |c| state_consume(c, "s2", 200.0))
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn audit_roundtrip_with_filters() {
        let (_t, d) = db();
        d.call(move |c| {
            audit_append(
                c,
                1.0,
                Some("github:1"),
                Some("alice"),
                "login",
                None,
                "ok",
                None,
                None,
            )?;
            audit_append(
                c,
                2.0,
                Some("github:2"),
                Some("bob"),
                "job.submit",
                Some("j1"),
                "ok",
                None,
                None,
            )?;
            audit_append(
                c,
                3.0,
                None,
                None,
                "login_failed",
                None,
                "denied",
                Some("1.2.3.4"),
                None,
            )
        })
        .await
        .unwrap();
        let all = d
            .call(|c| audit_query(c, None, None, None, 100))
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0]["action"], "login_failed");
        let logins = d
            .call(|c| audit_query(c, None, Some("login"), None, 100))
            .await
            .unwrap();
        assert_eq!(logins.len(), 1);
        let recent = d
            .call(|c| audit_query(c, None, None, Some(1.5), 100))
            .await
            .unwrap();
        assert_eq!(recent.len(), 2);
    }

    #[tokio::test]
    async fn old_schema_db_is_upgraded_in_place() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("auth.sqlite");
        {
            // The pre-M1 schema: no sessions.label, no principals.deleted_at, no role_grants.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE principals(
                   sub TEXT PRIMARY KEY, provider TEXT NOT NULL, login TEXT NOT NULL,
                   name TEXT, email TEXT, avatar_url TEXT,
                   first_seen REAL NOT NULL, last_seen REAL NOT NULL);
                 CREATE TABLE sessions(
                   token_sha256 TEXT PRIMARY KEY, sub TEXT NOT NULL, kind TEXT NOT NULL,
                   created_at REAL NOT NULL, expires_at REAL NOT NULL, last_seen REAL NOT NULL,
                   revoked_at REAL, user_agent TEXT, ip TEXT, provider_token TEXT);",
            )
            .unwrap();
            c.execute(
                "INSERT INTO principals VALUES('github:1','static','alice',NULL,NULL,NULL,10.0,20.0)",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO sessions VALUES('sha1','github:1','web',10.0,9999.0,20.0,NULL,'ua','ip',NULL)",
                [],
            )
            .unwrap();
        }
        let d = AuthDb::open(&path).unwrap();
        let upgraded = d
            .call(|c| {
                let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
                let p = get_principal(c, "github:1")?
                    .ok_or_else(|| AuthError::internal("row lost in migration"))?;
                let sessions = list_sessions(c, "github:1")?;
                let grants = grants_for(c, "github:1")?;
                Ok((version, p, sessions, grants))
            })
            .await
            .unwrap();
        assert_eq!(upgraded.0, 3);
        assert_eq!(
            (
                upgraded.1.first_seen,
                upgraded.1.last_seen,
                upgraded.1.deleted_at
            ),
            (10.0, 20.0, None)
        );
        assert_eq!(upgraded.2.len(), 1);
        assert_eq!(upgraded.2[0].label, None, "migrated column reads back NULL");
        assert!(upgraded.3.is_empty(), "role_grants exists and is empty");
        // Reopening an already-migrated file is a no-op (probes skip, version holds).
        drop(d);
        let d2 = AuthDb::open(&path).unwrap();
        let v2 = d2
            .call(|c| Ok(c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?))
            .await
            .unwrap();
        assert_eq!(v2, 3);
    }

    #[tokio::test]
    async fn tombstone_scrubs_identity_and_revokes_everything() {
        let (_t, d) = db();
        let now = rvbench_protocol::seconds();
        let user = ProviderUser {
            sub: "github:7".into(),
            login: "carol".into(),
            name: Some("Carol".into()),
            email: Some("c@x.io".into()),
            avatar_url: Some("https://a/7.png".into()),
        };
        d.call(move |c| {
            upsert_principal(c, &user, "static", 100.0)?;
            insert_session(c, "s1", "github:7", "web", 3600.0, None, None, None, 100.0)?;
            insert_session(c, "s2", "github:7", "cli", 86400.0, None, None, None, 100.0)?;
            cache_put(c, "github:7", true, false, 100.0, 300.0)
        })
        .await
        .unwrap();
        let expected = format!(
            "deleted-{}",
            &crate::auth::session::sha256_hex("carol")[..8]
        );
        let got = d
            .call(move |c| tombstone_principal(c, "github:7", now))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.login, expected);
        assert_eq!((got.name, got.email, got.avatar_url), (None, None, None));
        assert_eq!(got.deleted_at, Some(now));
        let (all_revoked, cache) = d
            .call(move |c| {
                let rows = list_sessions(c, "github:7")?;
                let revoked = rows.iter().all(|s| s.revoked_at == Some(now));
                Ok((revoked, cache_get(c, "github:7", now + 1.0)?))
            })
            .await
            .unwrap();
        assert!(all_revoked, "every session of the sub is revoked");
        assert!(cache.is_none(), "role_cache row is dropped");
        // Unknown sub is a no-op; repeating on a tombstoned row stays safe.
        assert!(
            d.call(move |c| tombstone_principal(c, "github:404", now))
                .await
                .unwrap()
                .is_none()
        );
        let again = d
            .call(move |c| tombstone_principal(c, "github:7", now + 5.0))
            .await
            .unwrap();
        assert!(again.unwrap().login.starts_with("deleted-"));
    }

    #[tokio::test]
    async fn grant_revoke_roundtrip() {
        let (_t, d) = db();
        let out = d
            .call(|c| {
                grant_roles(c, "github:1", &["admin", "early_access"], "github:9", 100.0)?;
                let both = grants_for(c, "github:1")?;
                revoke_roles(c, "github:1", &["early_access"], 200.0)?;
                let after_revoke = grants_for(c, "github:1")?;
                grant_roles(c, "github:2", &["admin"], "github:9", 250.0)?;
                revoke_roles(c, "github:2", &["admin"], 260.0)?;
                let admins = admin_grant_subs(c)?;
                revoke_roles(c, "github:1", &["nosuch"], 300.0)?; // missing row: no-op
                grant_roles(c, "github:1", &["early_access"], "github:8", 400.0)?; // re-grant revives
                let regranted = grants_for(c, "github:1")?;
                let stamp: (String, f64, Option<f64>) = c.query_row(
                    "SELECT granted_by,granted_at,revoked_at FROM role_grants
                     WHERE sub='github:1' AND role='early_access'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                Ok((both, after_revoke, admins, regranted, stamp))
            })
            .await
            .unwrap();
        assert_eq!(out.0, vec!["admin".to_string(), "early_access".to_string()]);
        assert_eq!(out.1, vec!["admin".to_string()]);
        assert_eq!(
            out.2,
            vec!["github:1".to_string()],
            "revoked admin is not listed"
        );
        assert_eq!(out.3, vec!["admin".to_string(), "early_access".to_string()]);
        assert_eq!(out.4, ("github:8".to_string(), 400.0, Option::<f64>::None));
        let (_, regranted_at, revoked_at) = out.4;
        assert_eq!(regranted_at, 400.0, "UPSERT restamps granted_at");
        assert_eq!(revoked_at, None, "UPSERT clears revoked_at");
    }

    #[tokio::test]
    async fn list_users_filters_roles_and_pages() {
        let (_t, d) = db();
        d.call(|c| {
            for (sub, login, name, seen) in [
                ("github:1", "alice", Some("Zeta"), 100.0),
                ("github:2", "bob", None, 200.0),
                ("github:3", "carol", Some("A%Z"), 300.0),
                ("github:4", "dave", None, 400.0),
            ] {
                let u = ProviderUser {
                    sub: sub.into(),
                    login: login.into(),
                    name: name.map(|s| s.to_string()),
                    email: None,
                    avatar_url: None,
                };
                upsert_principal(c, &u, "static", seen)?;
            }
            grant_roles(c, "github:1", &["admin"], "github:0", 50.0)?;
            grant_roles(c, "github:2", &["early_access"], "github:0", 50.0)?;
            cache_put(c, "github:3", true, true, 50.0, 300.0) // degraded cache row still counts
        })
        .await
        .unwrap();
        fn logins(rows: &[UserRow]) -> Vec<&str> {
            rows.iter().map(|u| u.login.as_str()).collect()
        }
        let all = d.call(|c| list_users(c, None, None, 10, 0)).await.unwrap();
        assert_eq!(
            logins(&all.0),
            ["dave", "carol", "bob", "alice"],
            "first_seen DESC"
        );
        assert!(!all.1);
        assert_eq!(all.0[3].db_roles, vec!["admin".to_string()]);
        assert_eq!(all.0[1].first_seen, 300.0);
        // q matches login or name; LIKE wildcards in the input stay literal.
        assert_eq!(
            logins(
                &d.call(|c| list_users(c, Some("li"), None, 10, 0))
                    .await
                    .unwrap()
                    .0
            ),
            ["alice"]
        );
        assert_eq!(
            logins(
                &d.call(|c| list_users(c, Some("Zeta"), None, 10, 0))
                    .await
                    .unwrap()
                    .0
            ),
            ["alice"]
        );
        assert_eq!(
            logins(
                &d.call(|c| list_users(c, Some("%"), None, 10, 0))
                    .await
                    .unwrap()
                    .0
            ),
            ["carol"]
        );
        assert!(
            d.call(|c| list_users(c, Some("zzz"), None, 10, 0))
                .await
                .unwrap()
                .0
                .is_empty()
        );
        // role filter: DB grants, plus role_cache for early_access.
        assert_eq!(
            logins(
                &d.call(|c| list_users(c, None, Some("admin"), 10, 0))
                    .await
                    .unwrap()
                    .0
            ),
            ["alice"]
        );
        assert_eq!(
            logins(
                &d.call(|c| list_users(c, None, Some("early_access"), 10, 0))
                    .await
                    .unwrap()
                    .0
            ),
            ["carol", "bob"]
        );
        assert_eq!(
            logins(
                &d.call(|c| list_users(c, None, Some("worker"), 10, 0))
                    .await
                    .unwrap()
                    .0
            )
            .len(),
            4
        );
        // limit+1 probing: page 1 knows a page 2 exists, last page says no.
        let page1 = d.call(|c| list_users(c, None, None, 2, 0)).await.unwrap();
        assert_eq!(logins(&page1.0), ["dave", "carol"]);
        assert!(page1.1);
        let page2 = d.call(|c| list_users(c, None, None, 2, 2)).await.unwrap();
        assert_eq!(logins(&page2.0), ["bob", "alice"]);
        assert!(!page2.1);
        let past = d.call(|c| list_users(c, None, None, 2, 4)).await.unwrap();
        assert!(past.0.is_empty() && !past.1);
    }

    #[tokio::test]
    async fn session_label_roundtrip_on_memory_db() {
        // memory() shares init/migrate with open(), so this also covers the fresh path.
        let d = AuthDb::memory().unwrap();
        let now = rvbench_protocol::seconds();
        let user = ProviderUser {
            sub: "github:1".into(),
            login: "alice".into(),
            name: None,
            email: None,
            avatar_url: None,
        };
        d.call(move |c| {
            upsert_principal(c, &user, "static", now)?;
            insert_session(
                c, "sha1", "github:1", "token", 3600.0, None, None, None, now,
            )
        })
        .await
        .unwrap();
        let first = d
            .call(|c| Ok(list_sessions(c, "github:1")?[0].clone()))
            .await
            .unwrap();
        assert_eq!(first.label, None);
        d.call(|c| set_session_label(c, "sha1", Some("laptop")))
            .await
            .unwrap();
        let labeled = d
            .call(|c| Ok(list_sessions(c, "github:1")?[0].clone()))
            .await
            .unwrap();
        assert_eq!(labeled.label.as_deref(), Some("laptop"));
        d.call(|c| set_session_label(c, "sha1", None))
            .await
            .unwrap();
        let cleared = d
            .call(|c| Ok(list_sessions(c, "github:1")?[0].clone()))
            .await
            .unwrap();
        assert_eq!(cleared.label, None);
    }
}

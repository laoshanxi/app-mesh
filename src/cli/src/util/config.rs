use anyhow::{Context, Result};
use appmesh::{OAuthConfig, TokenSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DEFAULT_WSS_PORT: u16 = 6063;

/// Same override the daemon applies on config.yaml (it also creates the leaf
/// when the file lacks it), so the CLI's local transport inference must honor
/// it too. See docs/source/TLS.md.
pub const ENV_REST_SSL_ENABLED: &str = "APPMESH_REST_SSL_SSLEnabled";

/// Deployment env names; the single spelling of each key.
pub const ENV_API_SECRET: &str = "APPMESH_API_SECRET";
pub const ENV_API_KEY: &str = "APPMESH_API_KEY";
pub const ENV_BEARER_TOKEN: &str = "APPMESH_BEARER_TOKEN";
pub const ENV_HOME: &str = "APPMESH_HOME";
pub const ENV_AUTH_ALLOW_HTTP: &str = "APPMESH_AUTH_ALLOW_HTTP";
pub const ENV_AUTH_ACCESS_URL: &str = "APPMESH_AUTH_ACCESS_URL";

/// Persisted config version 2: endpoint transport, verification, absolute CA path.
pub const CONFIG_VERSION: u32 = 2;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct CliConfig {
    #[serde(default)]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_port: Option<u16>,
    /// CA bundle trusted for last_host, remembered from `--ca-cert` at logon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ca_cert: Option<PathBuf>,
    /// The last endpoint speaks plaintext (ws://) instead of TLS (wss://).
    #[serde(default)]
    pub last_plain: bool,
    /// The last endpoint's certificate is verified while connecting.
    #[serde(default = "verify_by_default")]
    pub last_verify_server: bool,
}

fn verify_by_default() -> bool {
    true
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            last_host: None,
            last_port: None,
            last_ca_cert: None,
            last_plain: false,
            last_verify_server: true,
        }
    }
}

/// The endpoint the CLI last reached, replayable without flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RememberedEndpoint {
    pub host: String,
    pub port: u16,
    pub plain: bool,
    pub verify_server: bool,
    pub ca_cert: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct DaemonTlsConfig {
    pub ca_cert: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub verify_server: bool,
    // A ws:// or http:// endpoint: the daemon listener is plaintext.
    pub plain: bool,
}

impl Default for DaemonTlsConfig {
    fn default() -> Self {
        Self { ca_cert: None, client_cert: None, client_key: None, verify_server: true, plain: false }
    }
}

fn app_dir_name() -> &'static str {
    #[cfg(any(windows, target_os = "macos"))]
    {
        "AppMesh"
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        "appmesh"
    }
}

pub fn config_dir() -> PathBuf {
    resolve_config_dir(state_root().as_deref())
}

fn session_dir() -> PathBuf {
    resolve_session_dir(state_root().as_deref())
}

/// The CLI state root override: a non-empty APPMESH_HOME holds the config and
/// OAuth session directories itself instead of sharing the OS locations, so
/// parallel operators on one OS account get real session isolation.
fn state_root() -> Option<PathBuf> {
    std::env::var(ENV_HOME).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// Keep the on-disk layout under the chosen base: the app-named directory with
/// the config file inside it, and the `oauth` leaf for sessions.
fn resolve_config_dir(state_root: Option<&Path>) -> PathBuf {
    let base = match state_root {
        Some(root) => root.to_path_buf(),
        None => dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")),
    };
    let dir = base.join(app_dir_name());
    let _ = std::fs::create_dir_all(&dir);
    set_mode(&dir, 0o700);
    dir
}

fn resolve_session_dir(state_root: Option<&Path>) -> PathBuf {
    let base = match state_root {
        Some(root) => root.to_path_buf(),
        None => dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")),
    };
    let dir = base.join(app_dir_name()).join("oauth");
    let _ = std::fs::create_dir_all(&dir);
    set_mode(&dir, 0o700);
    dir
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub version: u32,
    pub engine_endpoint: String,
    pub oauth: OAuthConfig,
    pub tokens: TokenSet,
    /// The signed-in principal's display name (or shortened principal id), so a
    /// logon can name the session it displaces. Sessions written before this
    /// field existed, and writers that cannot know it, carry `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

impl StoredSession {
    pub fn new(engine_endpoint: String, oauth: OAuthConfig, tokens: TokenSet, principal: Option<String>) -> Self {
        Self { version: 1, engine_endpoint, oauth, tokens, principal }
    }
}

fn config_path() -> PathBuf {
    config_dir().join(".appmesh.config")
}

pub fn shell_history_path() -> PathBuf {
    config_dir().join(".appmesh.shell.history")
}

fn session_file(session: &StoredSession) -> PathBuf {
    session_file_at(&session_dir(), session)
}

fn session_file_at(dir: &Path, session: &StoredSession) -> PathBuf {
    let material = format!(
        "{}\n{}\n{}\n{}",
        session.engine_endpoint,
        session.oauth.issuer,
        session.oauth.client_id,
        session.oauth.audience.as_deref().unwrap_or_default()
    );
    let digest = Sha256::digest(material.as_bytes());
    let name = digest.iter().map(|byte| format!("{:02x}", byte)).collect::<String>();
    dir.join(format!("{}.json", name))
}

/// Atomically persist a complete token set and its issuer/client/audience binding.
/// Refresh tokens remain in this CLI-owned file and are never copied to the Engine.
pub fn save_session(session: &StoredSession) -> Result<()> {
    save_session_in(&session_dir(), session)
}

fn save_session_in(dir: &Path, session: &StoredSession) -> Result<()> {
    ensure_private_directory(dir)?;
    // Read the victims before the write below supersedes them: a logon that
    // displaces a different principal for this endpoint was the silent
    // identity-swap foot-gun, so name what it replaces.
    let displaced = displaced_principals(dir, session);
    if let Some(notice) = replacement_notice(&session.engine_endpoint, &displaced, session.principal.as_deref()) {
        eprintln!("{}", notice);
    }
    let path = session_file_at(dir, session);
    let bytes = serde_json::to_vec_pretty(session).context("serialize OAuth session")?;
    let mut temp = tempfile::NamedTempFile::new_in(dir).context("create OAuth session file")?;
    set_mode_result(temp.path(), 0o600)?;
    temp.write_all(&bytes).context("write OAuth session")?;
    temp.write_all(b"\n").context("write OAuth session terminator")?;
    temp.as_file().sync_all().context("sync OAuth session")?;
    temp.persist(&path).map_err(|error| error.error).context("install OAuth session")?;
    set_mode_result(&path, 0o600)?;
    #[cfg(unix)]
    std::fs::File::open(dir).and_then(|directory| directory.sync_all()).context("sync OAuth session directory")?;

    // Exactly one active OAuth identity is selected per Engine endpoint. Remove stale
    // profiles only after the new session is durable.
    for entry in std::fs::read_dir(dir).context("list OAuth sessions")? {
        let entry = entry?;
        let candidate = entry.path();
        if candidate == path || candidate.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        if let Ok(existing) = read_session_file(&candidate) {
            if existing.engine_endpoint == session.engine_endpoint {
                std::fs::remove_file(candidate).context("remove superseded OAuth session")?;
            }
        }
    }
    Ok(())
}

/// Principals of the stored sessions for this endpoint that this write is
/// about to supersede. Unreadable files have no name to report and are skipped.
fn displaced_principals(dir: &Path, session: &StoredSession) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut principals = Vec::new();
    for entry in entries.flatten() {
        let candidate = entry.path();
        if candidate.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        if let Ok(existing) = read_session_file(&candidate) {
            if existing.engine_endpoint == session.engine_endpoint {
                if let Some(previous) = existing.principal {
                    if !principals.contains(&previous) {
                        principals.push(previous);
                    }
                }
            }
        }
    }
    principals
}

/// The one-line notice for a write that displaces a stored session of another
/// principal at the same endpoint; None when nothing is being displaced.
fn replacement_notice(endpoint: &str, displaced: &[String], current: Option<&str>) -> Option<String> {
    let mut replaced: Vec<&str> = Vec::new();
    for previous in displaced {
        if Some(previous.as_str()) != current && !replaced.contains(&previous.as_str()) {
            replaced.push(previous.as_str());
        }
    }
    (!replaced.is_empty())
        .then(|| format!("Notice: this sign-in replaces the stored session of {} for {}.", replaced.join(", "), endpoint))
}

pub fn load_session(engine_endpoint: &str) -> Result<Option<StoredSession>> {
    load_session_from(&session_dir(), engine_endpoint)
}

/// One unreadable, corrupt, or unsafe session file must not block the other
/// candidates: skip it with a warning and keep scanning. Unusable files are
/// never returned; only a directory where every candidate failed is an error.
fn load_session_from(dir: &Path, engine_endpoint: &str) -> Result<Option<StoredSession>> {
    ensure_private_directory(dir)?;
    let mut attempted = 0_usize;
    let mut failed = 0_usize;
    let mut last_error: Option<anyhow::Error> = None;
    for entry in std::fs::read_dir(dir).context("list OAuth sessions")? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        attempted += 1;
        let session = match read_session_file(&path) {
            Ok(session) => session,
            Err(error) => {
                eprintln!("Warning: skipping OAuth session file {}: {}", path.display(), error);
                failed += 1;
                last_error = Some(error);
                continue;
            }
        };
        if session.engine_endpoint == engine_endpoint {
            return Ok(Some(session));
        }
    }
    if attempted > 0 && attempted == failed {
        let error = last_error.expect("failed counter without an error");
        return Err(error.context("no usable OAuth session file"));
    }
    Ok(None)
}

pub fn delete_session(session: &StoredSession) -> Result<()> {
    let path = session_file(session);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove OAuth session {}", path.display())),
    }
}

/// Cross-process mutex for one session file. Concurrent `appm` starts share a
/// single refresh token; without serialization two refreshes race, the rotation
/// invalidates the loser's grant, and every later command demands a fresh
/// `appm logon`.
pub struct SessionLock {
    path: PathBuf,
    pid: u32,
}

const SESSION_LOCK_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(10);
const SESSION_LOCK_WAIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(15);
/// A readable holder pid is trusted for far longer than the plain stale
/// window, so a slow token refresh keeps its lock; only a pid that has held
/// for minutes (a recycled pid or a zombie) is declared gone.
const HOLDER_PID_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(120);

impl SessionLock {
    /// Blocks until the lock is acquired. A holder that died without releasing
    /// is recovered once its recorded pid is gone; a lock without a readable
    /// pid still falls back to the stale window.
    pub fn acquire(session: &StoredSession) -> Result<Self> {
        let dir = session_dir();
        ensure_private_directory(&dir)?;
        let path = session_file(session).with_extension("lock");
        Self::acquire_at(&path)
    }

    fn acquire_at(path: &Path) -> Result<Self> {
        let pid = std::process::id();
        let deadline = std::time::Instant::now() + SESSION_LOCK_WAIT_LIMIT;
        loop {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    // Name the holder so a waiter can tell a live process from a
                    // crashed one; a failed write only costs the mtime fallback.
                    let _ = write!(file, "{}", pid);
                    return Ok(Self { path: path.to_path_buf(), pid });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_holder_dead(path) {
                        let _ = std::fs::remove_file(path);
                        continue;
                    }
                    if std::time::Instant::now() > deadline {
                        anyhow::bail!("timed out waiting for the OAuth session lock {}", path.display());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("create OAuth session lock {}", path.display()))
                }
            }
        }
    }
}

/// True when the lock's holder is provably gone: the recorded pid is dead, or
/// the file is older than the stale window (the holder died between creating
/// the file and writing its pid, or a recycled pid / a zombie now answers for
/// the holder). A live holder is trusted far longer than the plain stale
/// window, but not forever.
fn lock_holder_dead(path: &Path) -> bool {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    if let Ok(pid) = content.trim().parse::<u32>() {
        if pid == std::process::id() {
            // Pid reuse: this process is a waiter, never the holder, so the
            // file's age is the only signal left.
        } else if !process_alive(pid) {
            return true;
        } else {
            // A live pid outranks the plain stale window: a holder refreshing
            // tokens can outlast it. Only a holder that has held for many
            // times the window is declared gone — that is the recycled-pid or
            // zombie case, not a slow refresh.
            return lock_older_than(path, HOLDER_PID_STALE_AFTER);
        }
    }
    lock_older_than(path, SESSION_LOCK_STALE_AFTER)
}

fn lock_older_than(path: &Path, limit: std::time::Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age > limit)
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // Signal 0 only probes existence; EPERM still means the process is there.
    let sent = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
    sent || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::System::Threading::OpenProcess;
    // PROCESS_QUERY_LIMITED_INFORMATION; a handle means the pid still exists.
    let handle = unsafe { OpenProcess(0x1000, 0, pid) };
    if !handle.is_null() {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        return true;
    }
    false
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        // Remove the lock only while it still names this process: a waiter may
        // already have stolen a lock we held past its holder's lifetime.
        let ours = std::fs::read_to_string(&self.path)
            .is_ok_and(|content| content.trim().parse::<u32>() == Ok(self.pid));
        if ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// What a session-file mutation should do after re-reading the file under the
/// cross-process lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionUpdate {
    /// The on-disk session still holds the refresh token this update started
    /// from; persist the new token set.
    Write,
    /// A parallel process already refreshed past this update; its on-disk token
    /// set is the only live one, so adopt it instead of clobbering.
    Adopt(TokenSet),
    /// The session is gone or rebound to another identity; touch nothing.
    Skip,
}

/// Decide a token update against the latest on-disk session. Refresh-token
/// rotation allows exactly one consumer per grant: once the disk no longer
/// holds the refresh token this update consumed, a parallel CLI won the
/// rotation and writing our tokens would destroy the working session.
pub fn decide_session_update(
    used_refresh: Option<&str>,
    disk: Option<&StoredSession>,
    binding: &StoredSession,
) -> SessionUpdate {
    let Some(disk) = disk else { return SessionUpdate::Skip };
    if disk.engine_endpoint != binding.engine_endpoint || disk.oauth != binding.oauth {
        return SessionUpdate::Skip;
    }
    if disk.tokens.refresh_token.as_deref() == used_refresh {
        SessionUpdate::Write
    } else {
        SessionUpdate::Adopt(disk.tokens.clone())
    }
}

/// Hold the cross-process session lock and hand the caller the freshest
/// on-disk session, so every session-file mutation decides against state it
/// just observed. The caller's result is returned with the lock released.
pub fn with_session_lock<T>(session: &StoredSession, update: impl FnOnce(Option<StoredSession>) -> Result<T>) -> Result<T> {
    let _guard = SessionLock::acquire(session)?;
    let latest = load_session(&session.engine_endpoint).ok().flatten();
    update(latest)
}

fn read_session_file(path: &Path) -> Result<StoredSession> {
    ensure_private_file(path)?;
    let bytes = std::fs::read(path).with_context(|| format!("read OAuth session {}", path.display()))?;
    let session: StoredSession =
        serde_json::from_slice(&bytes).with_context(|| format!("parse OAuth session {}", path.display()))?;
    if session.version != 1 || session.tokens.access_token.trim().is_empty() {
        anyhow::bail!("unsupported or incomplete OAuth session")
    }
    Ok(session)
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    set_mode_result(path, 0o700)?;
    Ok(())
}

fn ensure_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!("OAuth session {} is accessible by another user", path.display());
        }
    }
    #[cfg(windows)]
    {
        if !crate::util::winacl::is_restricted(path)? {
            anyhow::bail!("OAuth session {} is accessible by another user", path.display());
        }
    }
    Ok(())
}

/// Remember the endpoint with the transport settings that reached it.
pub fn save_last_endpoint(endpoint: &RememberedEndpoint) {
    let cfg = CliConfig {
        version: CONFIG_VERSION,
        last_host: Some(endpoint.host.clone()),
        last_port: Some(endpoint.port),
        last_ca_cert: endpoint.ca_cert.as_deref().and_then(pin_ca_path),
        last_plain: endpoint.plain,
        last_verify_server: endpoint.verify_server,
    };
    persist_config(&cfg);
}

/// Pin the CA to an absolute path; symlinks stay unresolved so rotation behind the link survives.
/// A path that no longer resolves is not remembered.
fn pin_ca_path(path: &Path) -> Option<PathBuf> {
    let absolute = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir().ok()?.join(path) };
    absolute.exists().then_some(absolute)
}

pub fn load_last_endpoint() -> Option<RememberedEndpoint> {
    let cfg = load_config_at(&config_path())?;
    remembered_endpoint(&cfg)
}

fn remembered_endpoint(cfg: &CliConfig) -> Option<RememberedEndpoint> {
    Some(RememberedEndpoint {
        host: cfg.last_host.clone()?,
        port: cfg.last_port.unwrap_or(DEFAULT_WSS_PORT),
        plain: cfg.last_plain,
        verify_server: cfg.last_verify_server,
        ca_cert: cfg.last_ca_cert.clone(),
    })
}

/// Read the persisted config. A newer CLI's file is returned untouched:
/// rewriting it from this version would drop that format's fields.
fn load_config_at(path: &Path) -> Option<CliConfig> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn persist_config(cfg: &CliConfig) {
    let path = config_path();
    // Never replace a newer CLI's file: this version would drop its fields.
    if let Some(existing) = load_config_at(&path) {
        if existing.version > CONFIG_VERSION {
            return;
        }
    }
    persist_config_at(&path, cfg);
}

fn persist_config_at(path: &Path, cfg: &CliConfig) {
    let Ok(content) = serde_json::to_string_pretty(cfg) else {
        return;
    };
    // Replace atomically: a parallel CLI may read at any time.
    let Some(dir) = path.parent() else {
        return;
    };
    let Ok(mut temp) = tempfile::NamedTempFile::new_in(dir) else {
        let _ = std::fs::write(path, content + "\n");
        set_mode(path, 0o600);
        return;
    };
    let written = set_mode_result(temp.path(), 0o600).is_ok()
        && temp.write_all(content.as_bytes()).is_ok()
        && temp.write_all(b"\n").is_ok();
    if !written {
        return;
    }
    if temp.persist(path).is_ok() {
        set_mode(path, 0o600);
    }
}

/// Resolve the daemon's effective plaintext state: the
/// APPMESH_REST_SSL_SSLEnabled env override wins over the config.yaml value,
/// mirroring the daemon (Configuration::applyEnvConfig for a bool target: a
/// numeric value enables when > 0, any other string enables only when exactly
/// "true"; an empty value therefore disables). Malformed input the daemon's
/// std::stoi would tolerate ("5x") is treated as non-numeric here.
fn env_ssl_plain(value: Option<&str>, file_plain: bool) -> bool {
    match value {
        None => file_plain,
        Some(v) => match v.parse::<i64>() {
            Ok(n) => n <= 0,
            Err(_) => v != "true",
        },
    }
}

/// Read daemon config.yaml for TLS config and WSS port.
pub fn load_daemon_config() -> (Option<(String, u16)>, DaemonTlsConfig) {
    // The env override applies even when no config file is found: the daemon
    // creates the missing leaf, so it alone can switch the listeners to plain.
    let ssl_env = std::env::var(ENV_REST_SSL_ENABLED).ok();
    let appmesh_home = detect_appmesh_home();
    let config_path = appmesh_home.as_ref().and_then(|home| detect_daemon_config_file(home));

    let Some(config_path) = config_path else {
        return (None, DaemonTlsConfig { plain: env_ssl_plain(ssl_env.as_deref(), false), ..DaemonTlsConfig::default() });
    };

    let Ok(content) = std::fs::read_to_string(&config_path) else {
        return (None, DaemonTlsConfig::default());
    };

    let mut in_rest = false;
    let mut in_ssl = false;
    let mut rest_address: Option<String> = None;
    let mut wss_port: Option<u16> = None;
    let mut verify_server = true;
    // The daemon's SSLEnabled=false means the local listeners are plaintext.
    let mut plain = false;
    let mut ca_cert: Option<PathBuf> = None;
    let mut client_cert: Option<PathBuf> = None;
    let mut client_key: Option<PathBuf> = None;

    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim_end();
        if line.trim().is_empty() {
            continue;
        }

        let indent = line.chars().take_while(|ch| *ch == ' ').count();
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"').trim_matches('\'');

        if indent == 0 {
            in_rest = key == "REST";
            in_ssl = false;
            continue;
        }
        if !in_rest {
            continue;
        }
        if indent == 2 {
            in_ssl = key == "SSL" && value.is_empty();
            match key {
                "RestListenAddress" => rest_address = Some(value.to_string()),
                "WebSocketPort" => wss_port = value.parse().ok(),
                _ => {}
            }
            continue;
        }
        if in_ssl && indent >= 4 {
            match key {
                "SSLCaPath" => ca_cert = Some(PathBuf::from(value)),
                "SSLClientCertificateFile" => client_cert = Some(PathBuf::from(value)),
                "SSLClientCertificateKeyFile" => client_key = Some(PathBuf::from(value)),
                "VerifyServer" => verify_server = value.eq_ignore_ascii_case("true"),
                "SSLEnabled" => plain = value.eq_ignore_ascii_case("false"),
                _ => {}
            }
        }
    }

    let address = rest_address.map(|addr| {
        let host = if addr == "0.0.0.0" { "127.0.0.1".to_string() } else { addr };
        (host, wss_port.unwrap_or(DEFAULT_WSS_PORT))
    });

    let home = appmesh_home.unwrap_or_else(|| {
        #[cfg(unix)]
        {
            PathBuf::from("/opt/appmesh")
        }
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\local\appmesh")
        }
    });
    let tls = DaemonTlsConfig {
        ca_cert: ca_cert.map(|p| resolve_path(&home, &p)),
        client_cert: client_cert.map(|p| resolve_path(&home, &p)),
        client_key: client_key.map(|p| resolve_path(&home, &p)),
        verify_server,
        plain: env_ssl_plain(ssl_env.as_deref(), plain),
    };

    (address, tls)
}

fn detect_appmesh_home() -> Option<PathBuf> {
    if let Ok(home) = std::env::var(ENV_HOME) {
        let p = PathBuf::from(home);
        if p.exists() {
            return Some(p);
        }
    }
    #[cfg(unix)]
    {
        let path = PathBuf::from("/opt/appmesh");
        if path.exists() {
            return Some(path);
        }
    }
    #[cfg(windows)]
    {
        let path = PathBuf::from(r"C:\local\appmesh");
        if path.exists() {
            return Some(path);
        }
    }
    let exe = std::env::current_exe().ok()?;
    exe.parent()?.parent().map(Path::to_path_buf)
}

fn detect_daemon_config_file(home: &Path) -> Option<PathBuf> {
    [home.join("work").join("config").join("config.yaml"), home.join("config").join("config.yaml"), home.join("config.yaml")]
        .into_iter()
        .find(|p| p.exists())
}

fn resolve_path(home: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        home.join(path)
    }
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(windows)]
    {
        if mode & 0o077 == 0 {
            let _ = crate::util::winacl::restrict_to_current_user(path);
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, mode);
    }
}

fn set_mode_result(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("secure permissions on {}", path.display()))?;
    }
    #[cfg(windows)]
    {
        if mode & 0o077 == 0 {
            crate::util::winacl::restrict_to_current_user(path)?;
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(path: &Path, json: &str) {
        std::fs::write(path, json).expect("write test config");
    }

    #[test]
    fn env_ssl_plain_mirrors_the_daemon_coercion() {
        // Unset: the config.yaml value decides.
        assert!(!env_ssl_plain(None, false));
        assert!(env_ssl_plain(None, true));
        // "false" and any non-"true" string switch to plain, like the daemon.
        assert!(env_ssl_plain(Some("false"), false));
        assert!(env_ssl_plain(Some("false"), true));
        assert!(env_ssl_plain(Some(""), true));
        assert!(env_ssl_plain(Some("TRUE"), false));
        assert!(!env_ssl_plain(Some("true"), true));
        assert!(!env_ssl_plain(Some("true"), false));
        // Numeric coercion: > 0 keeps TLS, zero or negative goes plain.
        assert!(!env_ssl_plain(Some("1"), true));
        assert!(!env_ssl_plain(Some("+5"), true));
        assert!(env_ssl_plain(Some("0"), false));
        assert!(env_ssl_plain(Some("00"), false));
        assert!(env_ssl_plain(Some("-2"), false));
    }

    #[test]
    fn endpoint_transport_settings_roundtrip() {
        let dir = tempfile::tempdir().expect("create config directory");
        let path = dir.path().join("config.json");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, "-----BEGIN CERTIFICATE-----\n").expect("write CA");

        persist_config_at(
            &path,
            &CliConfig {
                version: CONFIG_VERSION,
                last_host: Some("10.0.0.5".into()),
                last_port: Some(6063),
                last_ca_cert: Some(ca.clone()),
                last_plain: false,
                last_verify_server: false,
            },
        );
        let cfg = load_config_at(&path).expect("reload config");
        assert_eq!(cfg.last_host.as_deref(), Some("10.0.0.5"));
        assert_eq!(cfg.last_ca_cert.as_deref(), Some(ca.as_path()));
        assert!(!cfg.last_plain);
        assert!(!cfg.last_verify_server, "an explicit verify choice must survive");
    }

    #[test]
    fn plain_endpoint_settings_roundtrip() {
        let dir = tempfile::tempdir().expect("create config directory");
        let path = dir.path().join("config.json");

        persist_config_at(
            &path,
            &CliConfig {
                version: CONFIG_VERSION,
                last_host: Some("gateway.example".into()),
                last_port: Some(6063),
                last_ca_cert: None,
                last_plain: true,
                last_verify_server: true,
            },
        );
        let cfg = load_config_at(&path).expect("reload config");
        assert!(cfg.last_plain, "the no-TLS choice must survive");
        assert_eq!(cfg.last_host.as_deref(), Some("gateway.example"));
    }

    #[test]
    fn stored_fields_load_as_written() {
        // The loader never repairs or drops fields; an unusable CA path
        // surfaces later as the CA loader's own error.
        let dir = tempfile::tempdir().expect("create config directory");
        let path = dir.path().join("config.json");
        let missing = dir.path().join("gone.pem");
        write_config(
            &path,
            &format!(
                r#"{{"version":2,"last_host":"10.0.0.5","last_port":6063,"last_ca_cert":{},"last_verify_server":false}}"#,
                serde_json::to_string(&missing).expect("serialize path")
            ),
        );

        let cfg = load_config_at(&path).expect("load config");
        assert_eq!(cfg.last_host.as_deref(), Some("10.0.0.5"));
        assert_eq!(cfg.last_ca_cert.as_deref(), Some(missing.as_path()));
    }

    #[test]
    fn newer_config_is_never_rewritten() {
        // A later CLI may add fields; reading must not drop or repair them.
        let dir = tempfile::tempdir().expect("create config directory");
        let path = dir.path().join("config.json");
        let missing = dir.path().join("gone.pem");
        let content = format!(
            r#"{{"version":99,"last_host":"10.0.0.5","last_port":6063,"last_ca_cert":{},"future_field":true}}"#,
            serde_json::to_string(&missing).expect("serialize path")
        );
        write_config(&path, &content);

        let cfg = load_config_at(&path).expect("load future config");
        assert_eq!(cfg.version, 99);
        assert_eq!(cfg.last_host.as_deref(), Some("10.0.0.5"));
        assert_eq!(cfg.last_ca_cert.as_deref(), Some(missing.as_path()));
        assert_eq!(std::fs::read_to_string(&path).expect("read future config"), content);
    }

    #[test]
    fn remembered_ca_is_pinned_to_an_absolute_path() {
        let dir = tempfile::tempdir().expect("create config directory");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, "-----BEGIN CERTIFICATE-----\n").expect("write CA");

        assert_eq!(pin_ca_path(&ca), Some(ca.clone()));
        assert_eq!(pin_ca_path(&dir.path().join("missing.pem")), None);
    }

    #[cfg(unix)]
    #[test]
    fn remembered_ca_keeps_symlink_indirection() {
        // Rotation swaps the certificate behind a stable symlink.
        let dir = tempfile::tempdir().expect("create config directory");
        let target = dir.path().join("ca-2026.pem");
        std::fs::write(&target, "-----BEGIN CERTIFICATE-----\n").expect("write CA");
        let link = dir.path().join("ca.pem");
        std::os::unix::fs::symlink(&target, &link).expect("create CA symlink");

        assert_eq!(pin_ca_path(&link), Some(link));
    }

    fn test_session(endpoint: &str) -> StoredSession {
        StoredSession::new(
            endpoint.to_string(),
            OAuthConfig::new("https://auth.example", "https://auth.example", "appmesh-cli"),
            TokenSet {
                access_token: "access-token".into(),
                refresh_token: Some("refresh-token".into()),
                expires_at: Some(4_102_444_800),
                refresh_at: None,
                token_type: "Bearer".into(),
                scope: None,
            },
            None,
        )
    }

    fn write_session(path: &Path, session: &StoredSession) {
        let bytes = serde_json::to_vec_pretty(session).expect("serialize test session");
        std::fs::write(path, bytes).expect("write test session");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("restrict test session");
        }
    }

    #[test]
    fn load_session_skips_broken_candidate_files() {
        let dir = tempfile::tempdir().expect("create session directory");
        let other = test_session("wss://other:6063");
        let wanted = test_session("wss://engine:6063");
        write_session(&dir.path().join("other.json"), &other);
        write_session(&dir.path().join("wanted.json"), &wanted);
        // Corrupt JSON must not abort the scan for the remaining candidates.
        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{ not valid json").expect("write broken session");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o600)).expect("restrict broken session");
        }

        let loaded = load_session_from(dir.path(), "wss://engine:6063").expect("broken candidate must not fail the load");
        assert_eq!(loaded.as_ref().map(|session| session.engine_endpoint.as_str()), Some("wss://engine:6063"));
        assert!(load_session_from(dir.path(), "wss://missing:6063").expect("scan succeeds").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn load_session_never_uses_loose_permission_files() {
        let dir = tempfile::tempdir().expect("create session directory");
        let wanted = test_session("wss://engine:6063");
        write_session(&dir.path().join("wanted.json"), &wanted);
        let leaky = dir.path().join("leaky.json");
        let leaky_session = test_session("wss://engine:6063");
        let bytes = serde_json::to_vec_pretty(&leaky_session).expect("serialize leaky session");
        std::fs::write(&leaky, bytes).expect("write leaky session");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&leaky, std::fs::Permissions::from_mode(0o644)).expect("loosen leaky session");
        }

        // The loose file is skipped, not fatal, and never returned.
        let loaded = load_session_from(dir.path(), "wss://engine:6063").expect("one safe candidate keeps the load usable");
        assert!(loaded.is_some(), "safe candidate must still be found");

        std::fs::remove_file(dir.path().join("wanted.json")).expect("drop safe candidate");
        let result = load_session_from(dir.path(), "wss://engine:6063");
        assert!(result.is_err(), "a session file with group/other bits must never be used");
    }

    #[test]
    fn load_session_errors_only_when_every_candidate_fails() {
        let dir = tempfile::tempdir().expect("create session directory");
        assert!(load_session_from(dir.path(), "wss://engine:6063").expect("empty directory is not an error").is_none());

        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "not json at all").expect("write broken session");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o600)).expect("restrict broken session");
        }
        assert!(load_session_from(dir.path(), "wss://engine:6063").is_err());
    }

    #[test]
    fn state_root_overrides_the_cli_state_dirs() {
        // Without the override the OS locations keep the existing layout.
        if let Some(base) = dirs::config_dir() {
            assert_eq!(resolve_config_dir(None), base.join(app_dir_name()));
        }
        if let Some(base) = dirs::data_local_dir() {
            assert_eq!(resolve_session_dir(None), base.join(app_dir_name()).join("oauth"));
        }
        // APPMESH_HOME becomes the state root with the same layout inside it.
        let home = PathBuf::from("/opt/operator-home");
        assert_eq!(resolve_config_dir(Some(&home)), home.join(app_dir_name()));
        assert_eq!(resolve_session_dir(Some(&home)), home.join(app_dir_name()).join("oauth"));
    }

    fn principal_session(endpoint: &str, principal: &str) -> StoredSession {
        let mut session = test_session(endpoint);
        session.principal = Some(principal.to_string());
        session
    }

    #[cfg(unix)]
    #[test]
    fn save_supersedes_the_endpoint_and_secures_the_files() {
        let dir = tempfile::tempdir().expect("create session directory");
        let mut first = principal_session("wss://engine:6063", "admin@appmesh.local");
        // A different issuer hashes to a different file at the same endpoint.
        first.oauth = OAuthConfig::new("https://other-auth", "https://other-auth", "appmesh-cli");
        save_session_in(dir.path(), &first).expect("save first profile");

        let second = principal_session("wss://engine:6063", "admin@appmesh.local");
        save_session_in(dir.path(), &second).expect("save second profile");

        // Exactly one session remains for the endpoint, and the private modes hold.
        let loaded = load_session_from(dir.path(), "wss://engine:6063").expect("load surviving session");
        let loaded = loaded.expect("one session survives the supersede");
        assert_eq!(loaded.principal.as_deref(), Some("admin@appmesh.local"));
        use std::os::unix::fs::PermissionsExt;
        let json_count = std::fs::read_dir(dir.path())
            .expect("list sessions")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("json"))
            .count();
        assert_eq!(json_count, 1, "the superseded profile must be removed");
        let file = session_file_at(dir.path(), &loaded);
        let mode = std::fs::metadata(&file).expect("session file metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "session files stay owner-only");
        let dir_mode = std::fs::metadata(dir.path()).expect("session dir metadata").permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "the session directory stays owner-only");
    }

    #[test]
    fn replacement_notice_names_only_other_principals() {
        let notice_for = |displaced: &[&str], current: Option<&str>| {
            replacement_notice(
                "wss://engine:6063",
                &displaced.iter().map(|name| name.to_string()).collect::<Vec<_>>(),
                current,
            )
        };
        // Displacing another principal is exactly the silent swap to surface.
        let notice = notice_for(&["admin@appmesh.local"], Some("guest@appmesh.local")).expect("must notice the swap");
        assert!(notice.contains("admin@appmesh.local"), "the replaced principal must be named: {}", notice);
        assert!(notice.contains("wss://engine:6063"));
        // Re-logging on as the same principal replaces nothing worth reporting.
        assert!(notice_for(&["guest@appmesh.local"], Some("guest@appmesh.local")).is_none());
        assert!(notice_for(&[], Some("guest@appmesh.local")).is_none());
        // An unnamed current principal must still warn about the one displaced.
        let notice = notice_for(&["admin@appmesh.local"], None).expect("unknown principal still displaces");
        assert!(notice.contains("admin@appmesh.local"));
        // Several displaced profiles are named once, on one line.
        let notice = notice_for(
            &["admin@appmesh.local", "viewer@appmesh.local", "admin@appmesh.local"],
            Some("guest@appmesh.local"),
        )
        .expect("must notice the swap");
        assert_eq!(notice.matches("admin@appmesh.local").count(), 1, "duplicates collapse: {}", notice);
        assert!(notice.contains("viewer@appmesh.local"));
        assert!(!notice.contains('\n'), "the notice stays on one line");
    }

    #[test]
    fn token_update_writes_only_while_the_disk_grant_is_ours() {
        let mut session = test_session("wss://engine:6063");
        session.tokens.refresh_token = Some("r1".into());

        // The disk still holds the grant this refresh consumed: safe to write.
        assert_eq!(decide_session_update(Some("r1"), Some(&session), &session), SessionUpdate::Write);
        // No refresh grant on either side (access-token-only session): still safe.
        let mut grantless = session.clone();
        grantless.tokens.refresh_token = None;
        assert_eq!(decide_session_update(None, Some(&grantless), &grantless), SessionUpdate::Write);

        // A parallel CLI rotated the grant: adopt its token set, never clobber it.
        let mut rotated = session.clone();
        rotated.tokens.access_token = "parallel-access".into();
        rotated.tokens.refresh_token = Some("r2".into());
        assert_eq!(
            decide_session_update(Some("r1"), Some(&rotated), &session),
            SessionUpdate::Adopt(rotated.tokens.clone())
        );

        // The session file is gone (logon replaced or removed it): touch nothing.
        assert_eq!(decide_session_update(Some("r1"), None, &session), SessionUpdate::Skip);

        // Another identity owns the endpoint now: never clobber or adopt it.
        let mut rebound = session.clone();
        rebound.oauth = OAuthConfig::new("https://other-auth", "https://other-auth", "appmesh-cli");
        assert_eq!(decide_session_update(Some("r1"), Some(&rebound), &session), SessionUpdate::Skip);
    }

    #[test]
    fn session_lock_names_its_holder_and_releases() {
        let dir = tempfile::tempdir().expect("create session directory");
        let path = dir.path().join("engine.lock");
        {
            let _guard = SessionLock::acquire_at(&path).expect("acquire fresh lock");
            let content = std::fs::read_to_string(&path).expect("read lock file");
            assert_eq!(content.trim(), std::process::id().to_string());
            // A live holder is never stale, however old the file may look.
            assert!(!lock_holder_dead(&path));
        }
        assert!(!path.exists(), "drop must remove a lock we still own");
    }

    #[cfg(unix)]
    #[test]
    fn session_lock_steals_only_dead_holders() {
        let dir = tempfile::tempdir().expect("create session directory");
        // A dead pid (an exited child) is recoverable immediately.
        let mut child = std::process::Command::new("true").spawn().expect("spawn short-lived child");
        let dead_pid = child.id();
        child.wait().expect("reap child");
        eventually(|| lock_holder_dead(&dead_lock_file(dir.path(), dead_pid)), "dead holder must be detected");

        // A live holder blocks the steal.
        let mut child = std::process::Command::new("sleep").arg("10").spawn().expect("spawn live child");
        let live = dir.path().join("live.lock");
        std::fs::write(&live, child.id().to_string()).expect("write live-holder lock");
        assert!(!lock_holder_dead(&live));
        let _ = child.kill();
        let _ = child.wait();

        // A lock with no readable pid falls back to the age window: fresh is not stale.
        let empty = dir.path().join("empty.lock");
        std::fs::write(&empty, "").expect("write empty lock");
        assert!(!lock_holder_dead(&empty));

        // acquire_at recovers the dead holder's lock without the stale wait.
        let stolen = SessionLock::acquire_at(&dead_lock_file(dir.path(), dead_pid)).expect("steal dead holder's lock");
        drop(stolen);
    }

    #[test]
    fn session_lock_drop_keeps_a_stolen_lock() {
        let dir = tempfile::tempdir().expect("create session directory");
        let path = dir.path().join("engine.lock");
        let guard = SessionLock::acquire_at(&path).expect("acquire fresh lock");
        // A waiter stole the file while we held it: our drop must not remove
        // theirs (pid 0 names no real process on any platform).
        std::fs::write(&path, "0").expect("overwrite with another holder");
        drop(guard);
        assert_eq!(std::fs::read_to_string(&path).expect("stolen lock survives").trim(), "0");
    }

    fn dead_lock_file(dir: &Path, pid: u32) -> PathBuf {
        let path = dir.join("dead.lock");
        std::fs::write(&path, pid.to_string()).expect("write dead-holder lock");
        path
    }

    fn eventually(condition: impl Fn() -> bool, what: &str) {
        for _ in 0..100 {
            if condition() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("{}", what);
    }
}

use anyhow::{Context, Result};
use appmesh::{DexOAuthConfig, TokenSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DEFAULT_WSS_PORT: u16 = 6058;

#[derive(Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CliConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct DaemonTlsConfig {
    pub ca_cert: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub verify_server: bool,
}

impl Default for DaemonTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert: None,
            client_cert: None,
            client_key: None,
            verify_server: true,
        }
    }
}

fn app_dir_name() -> &'static str {
    #[cfg(any(windows, target_os = "macos"))]
    { "AppMesh" }
    #[cfg(not(any(windows, target_os = "macos")))]
    { "appmesh" }
}

pub fn config_dir() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join(app_dir_name());
    let _ = std::fs::create_dir_all(&dir);
    set_mode(&dir, 0o700);
    dir
}

fn session_dir() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join(app_dir_name()).join("oauth");
    let _ = std::fs::create_dir_all(&dir);
    set_mode(&dir, 0o700);
    dir
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub version: u32,
    pub engine_endpoint: String,
    pub oauth: DexOAuthConfig,
    pub tokens: TokenSet,
}

impl StoredSession {
    pub fn new(engine_endpoint: String, oauth: DexOAuthConfig, tokens: TokenSet) -> Self {
        Self { version: 1, engine_endpoint, oauth, tokens }
    }
}

fn config_path() -> PathBuf {
    config_dir().join(".appmesh.config")
}

pub fn shell_history_path() -> PathBuf {
    config_dir().join(".appmesh.shell.history")
}

fn session_file(session: &StoredSession) -> PathBuf {
    let material = format!(
        "{}\n{}\n{}\n{}",
        session.engine_endpoint,
        session.oauth.issuer,
        session.oauth.client_id,
        session.oauth.audience.as_deref().unwrap_or_default()
    );
    let digest = Sha256::digest(material.as_bytes());
    let name = digest.iter().map(|byte| format!("{:02x}", byte)).collect::<String>();
    session_dir().join(format!("{}.json", name))
}

/// Atomically persist a complete Dex token set and its issuer/client/audience binding.
/// Refresh tokens remain in this CLI-owned file and are never copied to the Engine.
pub fn save_session(session: &StoredSession) -> Result<()> {
    let dir = session_dir();
    ensure_private_directory(&dir)?;
    let path = session_file(session);
    let bytes = serde_json::to_vec_pretty(session).context("serialize OAuth session")?;
    let mut temp = tempfile::NamedTempFile::new_in(&dir).context("create OAuth session file")?;
    set_mode_result(temp.path(), 0o600)?;
    temp.write_all(&bytes).context("write OAuth session")?;
    temp.write_all(b"\n").context("write OAuth session terminator")?;
    temp.as_file().sync_all().context("sync OAuth session")?;
    temp.persist(&path).map_err(|error| error.error).context("install OAuth session")?;
    set_mode_result(&path, 0o600)?;
    #[cfg(unix)]
    std::fs::File::open(&dir)
        .and_then(|directory| directory.sync_all())
        .context("sync OAuth session directory")?;

    // Exactly one active OAuth identity is selected per Engine endpoint. Remove stale
    // profiles only after the new session is durable.
    for entry in std::fs::read_dir(&dir).context("list OAuth sessions")? {
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

fn read_session_file(path: &Path) -> Result<StoredSession> {
    ensure_private_file(path)?;
    let bytes = std::fs::read(path).with_context(|| format!("read OAuth session {}", path.display()))?;
    let session: StoredSession = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse OAuth session {}", path.display()))?;
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
    Ok(())
}

pub fn save_last_host(host: &str, port: u16) {
    let cfg = CliConfig {
        last_host: Some(host.to_string()),
        last_port: Some(port),
    };
    if let Ok(content) = serde_json::to_string_pretty(&cfg) {
        let path = config_path();
        let _ = std::fs::write(&path, content + "\n");
        set_mode(&path, 0o600);
    }
}

pub fn load_last_host() -> Option<(String, u16)> {
    let content = std::fs::read_to_string(config_path()).ok()?;
    let cfg: CliConfig = serde_json::from_str(&content).ok()?;
    Some((cfg.last_host?, cfg.last_port.unwrap_or(DEFAULT_WSS_PORT)))
}

/// Read daemon config.yaml for TLS config and WSS port.
pub fn load_daemon_config() -> (Option<(String, u16)>, DaemonTlsConfig) {
    let appmesh_home = detect_appmesh_home();
    let config_path = appmesh_home
        .as_ref()
        .and_then(|home| detect_daemon_config_file(home));

    let Some(config_path) = config_path else {
        return (None, DaemonTlsConfig::default());
    };

    let Ok(content) = std::fs::read_to_string(&config_path) else {
        return (None, DaemonTlsConfig::default());
    };

    let mut in_rest = false;
    let mut in_ssl = false;
    let mut rest_address: Option<String> = None;
    let mut wss_port: Option<u16> = None;
    let mut verify_server = true;
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
        let Some((key, value)) = trimmed.split_once(':') else { continue };
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
        { PathBuf::from("/opt/appmesh") }
        #[cfg(windows)]
        { PathBuf::from(r"C:\local\appmesh") }
    });
    let tls = DaemonTlsConfig {
        ca_cert: ca_cert.map(|p| resolve_path(&home, &p)),
        client_cert: client_cert.map(|p| resolve_path(&home, &p)),
        client_key: client_key.map(|p| resolve_path(&home, &p)),
        verify_server,
    };

    (address, tls)
}

fn detect_appmesh_home() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("APPMESH_HOME") {
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
    [
        home.join("work").join("config").join("config.yaml"),
        home.join("config").join("config.yaml"),
        home.join("config.yaml"),
    ]
    .into_iter()
    .find(|p| p.exists())
}

fn resolve_path(home: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() { path.to_path_buf() } else { home.join(path) }
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    { let _ = (path, mode); }
}

fn set_mode_result(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("secure permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(endpoint: &str) -> StoredSession {
        StoredSession::new(
            endpoint.to_string(),
            DexOAuthConfig::new("https://dex.example", "https://dex.example", "appmesh-cli"),
            TokenSet {
                access_token: "access-token".into(),
                refresh_token: Some("refresh-token".into()),
                expires_at: Some(4_102_444_800),
                token_type: "Bearer".into(),
                scope: None,
            },
        )
    }

    fn write_session(path: &Path, session: &StoredSession) {
        let bytes = serde_json::to_vec_pretty(session).expect("serialize test session");
        std::fs::write(path, bytes).expect("write test session");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("restrict test session");
        }
    }

    #[test]
    fn load_session_skips_broken_candidate_files() {
        let dir = tempfile::tempdir().expect("create session directory");
        let other = test_session("wss://other:6058");
        let wanted = test_session("wss://engine:6058");
        write_session(&dir.path().join("other.json"), &other);
        write_session(&dir.path().join("wanted.json"), &wanted);
        // Corrupt JSON must not abort the scan for the remaining candidates.
        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{ not valid json").expect("write broken session");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o600))
                .expect("restrict broken session");
        }

        let loaded = load_session_from(dir.path(), "wss://engine:6058")
            .expect("broken candidate must not fail the load");
        assert_eq!(loaded.as_ref().map(|session| session.engine_endpoint.as_str()), Some("wss://engine:6058"));
        assert!(load_session_from(dir.path(), "wss://missing:6058").expect("scan succeeds").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn load_session_never_uses_loose_permission_files() {
        let dir = tempfile::tempdir().expect("create session directory");
        let wanted = test_session("wss://engine:6058");
        write_session(&dir.path().join("wanted.json"), &wanted);
        let leaky = dir.path().join("leaky.json");
        let leaky_session = test_session("wss://engine:6058");
        let bytes = serde_json::to_vec_pretty(&leaky_session).expect("serialize leaky session");
        std::fs::write(&leaky, bytes).expect("write leaky session");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&leaky, std::fs::Permissions::from_mode(0o644))
                .expect("loosen leaky session");
        }

        // The loose file is skipped, not fatal, and never returned.
        let loaded = load_session_from(dir.path(), "wss://engine:6058")
            .expect("one safe candidate keeps the load usable");
        assert!(loaded.is_some(), "safe candidate must still be found");

        std::fs::remove_file(dir.path().join("wanted.json")).expect("drop safe candidate");
        let result = load_session_from(dir.path(), "wss://engine:6058");
        assert!(result.is_err(), "a session file with group/other bits must never be used");
    }

    #[test]
    fn load_session_errors_only_when_every_candidate_fails() {
        let dir = tempfile::tempdir().expect("create session directory");
        assert!(
            load_session_from(dir.path(), "wss://engine:6058").expect("empty directory is not an error").is_none()
        );

        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "not json at all").expect("write broken session");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o600))
                .expect("restrict broken session");
        }
        assert!(load_session_from(dir.path(), "wss://engine:6058").is_err());
    }
}

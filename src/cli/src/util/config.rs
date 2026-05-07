use serde::{Deserialize, Serialize};
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

fn token_dir() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join(app_dir_name()).join("tokens");
    let _ = std::fs::create_dir_all(&dir);
    set_mode(&dir, 0o700);
    dir
}

pub fn host_safe_dir(host: &str) -> String {
    host.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | '[' | ']') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn config_path() -> PathBuf {
    config_dir().join(".appmesh.config")
}

pub fn shell_history_path() -> PathBuf {
    config_dir().join(".appmesh.shell.history")
}

fn token_file_for_host(host: &str) -> PathBuf {
    let host_dir = token_dir().join(host_safe_dir(host));
    let _ = std::fs::create_dir_all(&host_dir);
    set_mode(&host_dir, 0o700);
    host_dir.join(".token")
}

/// Save JWT token to a per-host file.
pub fn save_token(host: &str, token: &str) {
    let path = token_file_for_host(host);
    let _ = std::fs::write(&path, token);
    set_mode(&path, 0o600);
}

/// Load JWT token from a per-host file.
pub fn load_token(host: &str) -> Option<String> {
    let path = token_file_for_host(host);
    let token = std::fs::read_to_string(&path).ok()?;
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Remove persisted token for a host (on logoff).
pub fn clear_token(host: &str) {
    let path = token_file_for_host(host);
    let _ = std::fs::remove_file(&path);
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

    let home = appmesh_home.unwrap_or_else(|| PathBuf::from("/opt/appmesh"));
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
    let path = PathBuf::from("/opt/appmesh");
    if path.exists() {
        return Some(path);
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

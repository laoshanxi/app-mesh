use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use crate::app::AppmgpwdArgs;

pub fn appmgpwd(args: &AppmgpwdArgs) -> Result<i32> {
    if args.passwords.is_empty() {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let line = line?;
            let line = line.trim();
            if !line.is_empty() {
                println!("{}", hash_password(line));
            }
        }
    } else {
        for pwd in &args.passwords {
            println!("{}", hash_password(pwd));
        }
    }
    Ok(0)
}

pub fn appmginit() -> Result<i32> {
    // Root check (Unix only)
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 && !running_in_container() {
            bail!("Only root user can generate an initial password.");
        }
    }

    let appmesh_home = detect_appmesh_home()
        .context("Cannot detect App Mesh installation directory")?;

    // Flag file: only run once
    let work_dir = appmesh_home.join("work");
    let flag_file = work_dir.join(".appmginit");
    if flag_file.exists() {
        bail!("The 'appc appmginit' should only run once.");
    }

    // Read config.yaml
    let config_path = find_config_file(&appmesh_home, "config.yaml")
        .context("Cannot find config.yaml")?;
    let config_content = std::fs::read_to_string(&config_path)
        .context("Failed to read config.yaml")?;
    let mut config: serde_yaml::Value = serde_yaml::from_str(&config_content)
        .context("Failed to parse config.yaml")?;

    // Check JWT section exists
    let has_jwt = config
        .get("REST")
        .and_then(|r| r.get("JWT"))
        .is_some();

    if !has_jwt {
        bail!("No REST.JWT section found in config.yaml");
    }

    // Update JWT salt and algorithm
    let jwt_salt = generate_password(8);
    config["REST"]["JWT"]["JWTSalt"] = serde_yaml::Value::String(jwt_salt);
    config["REST"]["JWT"]["Algorithm"] = serde_yaml::Value::String("RS256".to_string());

    // Write config to work/config/ directory
    let write_config_dir = work_dir.join("config");
    std::fs::create_dir_all(&write_config_dir)
        .context("Failed to create work/config directory")?;
    let write_config_path = write_config_dir.join("config.yaml");
    let config_out = serde_yaml::to_string(&config)?;
    std::fs::write(&write_config_path, &config_out)
        .context("Failed to write config.yaml")?;

    // Check if using local security interface
    let security_interface = config["REST"]["JWT"]["SecurityInterface"]
        .as_str()
        .unwrap_or("");

    if security_interface == "local" {
        let security_path = find_config_file(&appmesh_home, "security.yaml")
            .context("Cannot find security.yaml")?;
        let security_content = std::fs::read_to_string(&security_path)
            .context("Failed to read security.yaml")?;
        let mut security: serde_yaml::Value = serde_yaml::from_str(&security_content)
            .context("Failed to parse security.yaml")?;

        // Enable encryption and set admin password
        security["EncryptKey"] = serde_yaml::Value::Bool(true);
        let gen_password = generate_password(8);
        let encrypted_password = hash_password(&gen_password);
        security["Users"]["admin"]["key"] = serde_yaml::Value::String(encrypted_password);

        // Write security.yaml to work/config/
        let write_security_path = write_config_dir.join("security.yaml");
        let security_out = serde_yaml::to_string(&security)?;
        std::fs::write(&write_security_path, &security_out)
            .context("Failed to write security.yaml")?;

        println!(
            "Important: This will only occur once, password for user <admin> is <{}>.",
            gen_password
        );
    }

    // Create flag file to prevent re-run
    std::fs::write(&flag_file, "")
        .context("Failed to create initialization flag file")?;

    Ok(0)
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn generate_password(length: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    // Mix in PID for extra entropy
    seed ^= std::process::id() as u64;

    let mut password = String::with_capacity(length);
    for i in 0..length {
        // Simple LCG PRNG (not cryptographic, matches C++ generatePassword intent)
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let idx = ((seed >> (16 + i as u64)) as usize) % charset.len();
        password.push(charset[idx] as char);
    }
    password
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

/// Find config file: prefer work/config/{name}, fall back to config/{name}
fn find_config_file(home: &Path, name: &str) -> Option<PathBuf> {
    let work_path = home.join("work").join("config").join(name);
    if work_path.exists() {
        return Some(work_path);
    }
    let config_path = home.join("config").join(name);
    if config_path.exists() {
        return Some(config_path);
    }
    None
}

fn running_in_container() -> bool {
    Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|s| s.contains("docker") || s.contains("kubepods"))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password() {
        let hash = hash_password("admin");
        assert_eq!(
            hash,
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
        );
    }

    #[test]
    fn test_hash_password_empty() {
        let hash = hash_password("");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_generate_password_length() {
        let pwd = generate_password(8);
        assert_eq!(pwd.len(), 8);
        assert!(pwd.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_password_unique() {
        let p1 = generate_password(16);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let p2 = generate_password(16);
        assert_ne!(p1, p2);
    }
}

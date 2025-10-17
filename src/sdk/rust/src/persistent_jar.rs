// persistent_jar.rs

use reqwest::cookie::{CookieStore, Jar};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use url::Url;

use crate::error::AppMeshError;

type Result<T> = std::result::Result<T, AppMeshError>;

/// PersistentJar wraps a reqwest::cookie::Jar and automatically saves to a file in libcurl format.
#[derive(Debug, Clone)]
pub struct PersistentJar {
    jar: Arc<Jar>,
    url: Url,
    file_path: PathBuf,
    io_lock: Arc<Mutex<()>>, // protects load/save operations
}

impl PersistentJar {
    /// Create a new PersistentJar for a single URL and cookie file.
    pub fn new(url: &str, file_path: impl AsRef<Path>) -> Result<Self> {
        let url = Url::parse(url).map_err(AppMeshError::from)?;
        let file_path = file_path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Initialize cookie file if not exists
        if !file_path.exists() {
            fs::write(&file_path, "# Netscape HTTP Cookie File\n")?;
        }

        let jar = Arc::new(Jar::default());
        let manager = Self { jar: jar.clone(), url, file_path, io_lock: Arc::new(Mutex::new(())) };

        manager.load()?; // Load existing cookies
        Ok(manager)
    }

    /// Load cookies from file into the jar (thread-safe)
    pub fn load(&self) -> Result<()> {
        let _guard = self.io_lock.lock().unwrap();
        let content = fs::read_to_string(&self.file_path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // libcurl format: domain\tTRUE/FALSE\tpath\tsecure\texpiry\tname\tvalue
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 7 {
                continue;
            }

            let name = parts[5];
            let value = parts[6];
            let cookie_str = format!("{name}={value}");
            self.jar.add_cookie_str(&cookie_str, &self.url);
        }
        Ok(())
    }

    /// Save cookies from jar to file (thread-safe)
    pub fn save(&self) -> Result<()> {
        let _guard = self.io_lock.lock().unwrap();
        let mut lines = vec!["# Netscape HTTP Cookie File".to_string()];

        if let Some(header_value) = self.jar.cookies(&self.url) {
            if let Ok(cookie_header) = header_value.to_str() {
                for pair in cookie_header.split("; ") {
                    let parts: Vec<&str> = pair.splitn(2, '=').collect();
                    if parts.len() != 2 {
                        continue;
                    }
                    let (name, value) = (parts[0], parts[1]);
                    let domain = self.url.host_str().unwrap_or("");
                    let path = "/";
                    let secure = if self.url.scheme() == "https" { "TRUE" } else { "FALSE" };
                    let expiry = 0; // skip expiry, could be added later

                    lines.push(format!("{}\tTRUE\t{}\t{}\t{}\t{}\t{}", domain, path, secure, expiry, name, value));
                }
            }
        }

        fs::write(&self.file_path, lines.join("\n"))?;
        Ok(())
    }

    /// Add or update a cookie and automatically save to file
    pub fn add_cookie(&self, cookie_str: &str) -> Result<()> {
        self.jar.add_cookie_str(cookie_str, &self.url);
        self.save()
    }

    /// Get a cookie value by name
    pub fn get_cookie(&self, name: &str) -> Option<String> {
        self.jar.cookies(&self.url).and_then(|header| {
            header.to_str().ok().and_then(|s| {
                // Parse the cookie header which is in format: "name1=value1; name2=value2"
                s.split("; ").find_map(|pair| {
                    let parts: Vec<&str> = pair.splitn(2, '=').collect();
                    if parts.len() == 2 && parts[0] == name {
                        Some(parts[1].to_string())
                    } else {
                        None
                    }
                })
            })
        })
    }

    /// Clear all cookies
    pub fn clear(&self) -> Result<()> {
        let _guard = self.io_lock.lock().unwrap();
        fs::write(&self.file_path, "# Netscape HTTP Cookie File\n")?;
        Ok(())
    }

    /// Return the underlying Jar for use with reqwest
    pub fn jar(&self) -> Arc<Jar> {
        self.jar.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_save_and_load() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Create and add cookies
        {
            let jar = PersistentJar::new("https://example.com", path).unwrap();
            jar.add_cookie("session=abc123").unwrap();
            jar.add_cookie("user=testuser").unwrap();
        }

        // Load again
        {
            let jar = PersistentJar::new("https://example.com", path).unwrap();
            assert_eq!(jar.get_cookie("session"), Some("abc123".to_string()));
            assert_eq!(jar.get_cookie("user"), Some("testuser".to_string()));
        }
    }
}

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

const NETSCAPE_HEADER: &str = "# Netscape HTTP Cookie File\n";

/// PersistentJar wraps a reqwest::cookie::Jar and automatically persists cookies
/// to disk in Netscape/libcurl format with thread safe.
#[derive(Debug, Clone)]
pub struct PersistentJar {
    jar: Arc<Jar>,
    url: Url,
    file_path: PathBuf,
    io_lock: Arc<Mutex<()>>,
}

impl PersistentJar {
    /// Creates a new PersistentJar for the specified URL and cookie file path.
    pub fn new(url: &str, file_path: impl AsRef<Path>) -> Result<Self> {
        let url = Url::parse(url).map_err(AppMeshError::from)?;
        let file_path = file_path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Initialize cookie file if it doesn't exist
        if !file_path.exists() {
            fs::write(&file_path, NETSCAPE_HEADER)?;
        }

        let jar = Arc::new(Jar::default());
        let manager = Self { jar: jar.clone(), url, file_path, io_lock: Arc::new(Mutex::new(())) };

        manager.load()?;
        Ok(manager)
    }

    /// Loads cookies from the file into the jar.
    pub fn load(&self) -> Result<()> {
        let _guard = self.io_lock.lock().unwrap();
        let content = fs::read_to_string(&self.file_path)?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Netscape format: domain\tflag\tpath\tsecure\texpiry\tname\tvalue
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 7 {
                continue; // Skip malformed lines
            }

            let (name, value) = (parts[5], parts[6]);
            let cookie_str = format!("{}={}", name, value);
            self.jar.add_cookie_str(&cookie_str, &self.url);
        }

        Ok(())
    }

    /// Saves all cookies from the jar to the file.
    pub fn save(&self) -> Result<()> {
        let _guard = self.io_lock.lock().unwrap();
        let mut lines = vec!["# Netscape HTTP Cookie File".to_string()];

        if let Some(header_value) = self.jar.cookies(&self.url) {
            if let Ok(cookie_header) = header_value.to_str() {
                let domain = self.url.host_str().unwrap_or("localhost");
                let secure = if self.url.scheme() == "https" { "TRUE" } else { "FALSE" };

                for pair in cookie_header.split("; ") {
                    if let Some((name, value)) = pair.split_once('=') {
                        // Format: domain\tflag\tpath\tsecure\texpiry\tname\tvalue
                        lines.push(format!("{}\tTRUE\t/\t{}\t0\t{}\t{}", domain, secure, name, value));
                    }
                }
            }
        }

        fs::write(&self.file_path, lines.join("\n") + "\n")?;
        Ok(())
    }

    /// Return the underlying Jar for use with reqwest
    pub fn jar(&self) -> Arc<Jar> {
        self.jar.clone()
    }

    /*
    /// Adds or updates a cookie and persists it to disk.
    pub fn add_cookie(&self, cookie_str: &str) -> Result<()> {
        self.jar.add_cookie_str(cookie_str, &self.url);
        self.save()
    }

    /// Retrieves a cookie value by name.
    pub fn get_cookie(&self, name: &str) -> Option<String> {
        self.jar.cookies(&self.url).and_then(|header| {
            header.to_str().ok().and_then(|cookie_header| {
                cookie_header.split("; ").find_map(|pair| {
                    pair.split_once('=').filter(|(key, _)| *key == name).map(|(_, value)| value.to_string())
                })
            })
        })
    }

    /// Clears all cookies and resets the file.
    pub fn clear(&self) -> Result<()> {
        let _guard = self.io_lock.lock().unwrap();
        fs::write(&self.file_path, NETSCAPE_HEADER)?;
        Ok(())
    }
    */
}

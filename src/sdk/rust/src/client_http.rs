// client.rs

use base64::Engine;
use log::{debug, error};
use reqwest::{cookie::CookieStore, cookie::Jar, header::HeaderValue, Client as ReqwestClient, Method, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::constants::*;
use crate::error::AppMeshError;
use crate::models::*;
use crate::persistent_jar::PersistentJar;

type Result<T> = std::result::Result<T, AppMeshError>;

/// Main AppMesh client for interacting with the AppMesh service
#[derive(Debug)]
pub struct AppMeshClient {
    client: ReqwestClient,
    pub persistent_jar: Option<PersistentJar>, // optional PersistentJar
    pub cookie_jar: Arc<Jar>,                  // always points to the jar used
    config: ClientConfig,
    forward_to: Option<String>,
}

impl AppMeshClient {
    //
    // Session/Client initialization
    //

    /// Create a new AppMesh client with the given configuration
    pub fn new(config: ClientConfig) -> Result<Arc<Self>> {
        // Cookie setup
        let (cookie_jar, persistent_jar) = if let Some(cookie_file) = &config.cookie_file {
            if !cookie_file.is_empty() {
                let pj = PersistentJar::new(&config.url, cookie_file)?;
                (pj.jar(), Some(pj))
            } else {
                (Arc::new(Jar::default()), None)
            }
        } else {
            (Arc::new(Jar::default()), None)
        };

        let mut client_builder =
            ReqwestClient::builder().cookie_provider(cookie_jar.clone()).timeout(Duration::from_secs(60));

        // SSL setup
        if let Some(ssl_verify) = &config.ssl_verify {
            let cert_bytes = std::fs::read(ssl_verify)?;
            client_builder = client_builder.add_root_certificate(reqwest::Certificate::from_pem(&cert_bytes)?);
        }

        if let (Some(cert), Some(key)) = (&config.ssl_client_cert, &config.ssl_client_key) {
            let cert_content = std::fs::read_to_string(cert)?;
            let key_content = std::fs::read_to_string(key)?;
            let pem = format!("{}\n{}", cert_content, key_content);
            let identity = reqwest::Identity::from_pem(pem.as_bytes())
                .map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
            client_builder = client_builder.identity(identity);
        }

        Ok(Arc::new(Self { client: client_builder.build()?, persistent_jar, cookie_jar, config, forward_to: None }))
    }

    /// Set forwarding host for requests
    pub fn forward_to(&mut self, url: Option<String>) {
        self.forward_to = url;
    }

    //
    // Authentication Management
    //

    /// Login with username and password
    /// Returns TOTP challenge string if TOTP is required, empty string on success
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        totp: Option<&str>,
        timeout_seconds: Option<i32>,
        audience: Option<&str>,
    ) -> Result<String> {
        let mut headers = HashMap::new();
        headers.insert(
            HTTP_HEADER_JWT_AUTHORIZATION.to_string(),
            format!(
                "{}{}",
                HTTP_HEADER_AUTH_BASIC,
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password))
            ),
        );
        headers.insert(HTTP_HEADER_JWT_SET_COOKIE.to_string(), "true".to_string());

        if let Some(seconds) = timeout_seconds {
            headers.insert(HTTP_HEADER_JWT_EXPIRE_SECONDS.to_string(), seconds.to_string());
        }
        if let Some(aud) = audience {
            headers.insert(HTTP_HEADER_JWT_AUDIENCE.to_string(), aud.to_string());
        }
        if let Some(totp_code) = totp {
            headers.insert(HTTP_HEADER_JWT_TOTP.to_string(), totp_code.to_string());
        }

        let response =
            self.request(Method::POST, "/appmesh/login", Option::<&Value>::None, Some(headers), None, false).await?;

        // Handle TOTP challenge (HTTP 428)
        if response.status() == StatusCode::PRECONDITION_REQUIRED {
            let json: Value = response.json().await?;
            if let Some(challenge) = json.get(REST_TEXT_TOTP_CHALLENGE_JSON_KEY) {
                return Ok(challenge.as_str().unwrap_or("").to_string());
            }
        } else if response.status() != StatusCode::OK {
            let text = response.text().await?;
            return Err(AppMeshError::AuthenticationFailed(text));
        }

        Ok(String::new()) // success
    }

    /// Validate TOTP code with challenge
    pub async fn validate_totp(&self, username: &str, challenge: &str, totp: &str, timeout_seconds: i32) -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_JWT_SET_COOKIE.to_string(), "true".to_string());

        let body = json!({
            HTTP_BODY_KEY_JWT_USERNAME: username,
            HTTP_BODY_KEY_JWT_TOTP: totp,
            HTTP_BODY_KEY_JWT_TOTP_CHALLENGE: challenge,
            HTTP_BODY_KEY_JWT_EXPIRE_SECONDS: timeout_seconds
        });

        self.request(Method::POST, "/appmesh/totp/validate", Some(&body), Some(headers), None, true).await?;
        Ok(())
    }

    /// Authenticate with JWT token
    /// Returns (success, message)
    pub async fn authenticate(
        &self,
        token: &str,
        permission: Option<&str>,
        audience: Option<&str>,
        apply: bool,
    ) -> Result<(bool, String)> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_JWT_AUTHORIZATION.to_string(), format!("{}{}", HTTP_HEADER_AUTH_BEARER, token));

        if let Some(perm) = permission {
            headers.insert(HTTP_HEADER_JWT_AUTH_PERMISSION.to_string(), perm.to_string());
        }
        if let Some(aud) = audience {
            headers.insert(HTTP_HEADER_JWT_AUDIENCE.to_string(), aud.to_string());
        }
        if apply {
            headers.insert(HTTP_HEADER_JWT_SET_COOKIE.to_string(), "true".to_string());
        }

        let resp = self.request(Method::POST, "/appmesh/auth", None::<&Value>, Some(headers), None, false).await?;

        let is_ok = resp.status() == StatusCode::OK;
        let text = resp.text().await?;
        Ok((is_ok, text))
    }

    /// Logout from current session
    pub async fn logout(&self) -> Result<()> {
        self.request(Method::POST, "/appmesh/self/logoff", None::<&Value>, None, None, true).await?;
        Ok(())
    }

    /// Renew JWT token
    pub async fn renew_token(&self, timeout_seconds: Option<i32>) -> Result<()> {
        let mut headers = HashMap::new();
        if let Some(sec) = timeout_seconds {
            headers.insert(HTTP_HEADER_JWT_EXPIRE_SECONDS.to_string(), sec.to_string());
        }

        self.request(Method::POST, "/appmesh/token/renew", None::<&Value>, Some(headers), None, true).await?;
        Ok(())
    }

    /// Get TOTP secret for MFA setup
    pub async fn get_totp_secret(&self) -> Result<String> {
        let resp = self.request(Method::POST, "/appmesh/totp/secret", None::<&Value>, None, None, true).await?;

        let val: Value = resp.json().await?;
        let encoded =
            val[HTTP_BODY_KEY_MFA_URI].as_str().ok_or_else(|| AppMeshError::Other("Invalid MFA URI".to_string()))?;

        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let totp_uri = String::from_utf8_lossy(&decoded).to_string();

        // Parse the TOTP URI to extract the secret
        let secret = Self::parse_totp_uri(&totp_uri)?;
        Ok(secret)
    }

    /// Parse TOTP URI and extract secret
    fn parse_totp_uri(uri: &str) -> Result<String> {
        // URI format: otpauth://totp/...?secret=XXX&issuer=...
        if let Some(query_start) = uri.find('?') {
            let query = &uri[query_start + 1..];
            for param in query.split('&') {
                if let Some(eq_pos) = param.find('=') {
                    let key = &param[..eq_pos];
                    let value = &param[eq_pos + 1..];
                    if key == "secret" {
                        return Ok(value.to_string());
                    }
                }
            }
        }
        Err(AppMeshError::Other("TOTP URI does not contain a 'secret' field".to_string()))
    }

    /// Enable TOTP with verification code
    pub async fn enable_totp(&self, totp: &str) -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_JWT_TOTP.to_string(), totp.to_string());

        self.request(Method::POST, "/appmesh/totp/setup", None::<&Value>, Some(headers), None, true).await?;
        Ok(())
    }

    /// Disable TOTP for user
    pub async fn disable_totp(&self, user: Option<&str>) -> Result<()> {
        let user = user.unwrap_or("self");
        self.request(Method::POST, &format!("/appmesh/totp/{}/disable", user), None::<&Value>, None, None, true)
            .await?;
        Ok(())
    }

    //
    // User Management
    //

    /// Update user password
    pub async fn update_password(&self, old: &str, new: &str, user: Option<&str>) -> Result<()> {
        let user = user.unwrap_or("self");
        let body = json!({
            HTTP_BODY_KEY_OLD_PASSWORD: base64::engine::general_purpose::STANDARD.encode(old),
            HTTP_BODY_KEY_NEW_PASSWORD: base64::engine::general_purpose::STANDARD.encode(new)
        });

        self.request(Method::POST, &format!("/appmesh/user/{}/passwd", user), Some(&body), None, None, true).await?;
        Ok(())
    }

    /// Get current user information
    pub async fn get_current_user(&self) -> Result<Value> {
        let r = self.request(Method::GET, "/appmesh/user/self", None::<&Value>, None, None, true).await?;
        Ok(r.json().await?)
    }

    /// List all users
    pub async fn list_users(&self) -> Result<Value> {
        let r = self.request(Method::GET, "/appmesh/users", None::<&Value>, None, None, true).await?;
        Ok(r.json().await?)
    }

    /// Add a new user
    pub async fn add_user(&self, user: Value) -> Result<()> {
        let name =
            user["name"].as_str().ok_or_else(|| AppMeshError::ConfigurationError("Missing username".to_string()))?;

        self.request(Method::PUT, &format!("/appmesh/user/{}", name), Some(&user), None, None, true).await?;
        Ok(())
    }

    /// Delete a user
    pub async fn delete_user(&self, user: &str) -> Result<()> {
        self.request(Method::DELETE, &format!("/appmesh/user/{}", user), None::<&Value>, None, None, true).await?;
        Ok(())
    }

    /// Lock a user account
    pub async fn lock_user(&self, user: &str) -> Result<()> {
        self.request(Method::POST, &format!("/appmesh/user/{}/lock", user), None::<&Value>, None, None, true).await?;
        Ok(())
    }

    /// Unlock a user account
    pub async fn unlock_user(&self, user: &str) -> Result<()> {
        self.request(Method::POST, &format!("/appmesh/user/{}/unlock", user), None::<&Value>, None, None, true).await?;
        Ok(())
    }

    /// List all groups
    pub async fn list_groups(&self) -> Result<Vec<String>> {
        let r = self.request(Method::GET, "/appmesh/user/groups", None::<&Value>, None, None, true).await?;

        let json: Value = r.json().await?;
        Ok(json.as_array().unwrap_or(&vec![]).iter().filter_map(|v| v.as_str().map(String::from)).collect())
    }

    /// Get current user's permissions
    pub async fn get_user_permissions(&self) -> Result<Vec<String>> {
        let r = self.request(Method::GET, "/appmesh/user/permissions", None::<&Value>, None, None, true).await?;

        let json: Value = r.json().await?;
        Ok(json.as_array().unwrap_or(&vec![]).iter().filter_map(|v| v.as_str().map(String::from)).collect())
    }

    /// List all available permissions
    pub async fn list_permissions(&self) -> Result<Vec<String>> {
        let r = self.request(Method::GET, "/appmesh/permissions", None::<&Value>, None, None, true).await?;

        let json: Value = r.json().await?;
        Ok(json.as_array().unwrap_or(&vec![]).iter().filter_map(|v| v.as_str().map(String::from)).collect())
    }

    /// List all roles
    pub async fn list_roles(&self) -> Result<HashMap<String, Vec<String>>> {
        let r = self.request(Method::GET, "/appmesh/roles", None::<&Value>, None, None, true).await?;

        let json: Value = r.json().await?;
        let mut roles = HashMap::new();

        if let Some(obj) = json.as_object() {
            for (key, value) in obj {
                if let Some(arr) = value.as_array() {
                    let perms: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    roles.insert(key.clone(), perms);
                }
            }
        }

        Ok(roles)
    }

    /// Update role permissions
    pub async fn update_role(&self, role: &str, permissions: Vec<String>) -> Result<()> {
        let body = json!(permissions);

        self.request(Method::POST, &format!("/appmesh/role/{}", role), Some(&body), None, None, true).await?;
        Ok(())
    }

    /// Delete a role
    pub async fn delete_role(&self, role: &str) -> Result<()> {
        self.request(Method::DELETE, &format!("/appmesh/role/{}", role), None::<&Value>, None, None, true).await?;
        Ok(())
    }

    //
    // Application Management
    //

    /// List all applications
    pub async fn list_apps(&self) -> Result<Vec<Application>> {
        let apps: Vec<Application> = self
            .request(Method::GET, "/appmesh/applications", None::<&Value>, None, None, true)
            .await?
            .json()
            .await
            .map_err(|e| AppMeshError::Other(format!("Deserialize error: {}", e)))?;

        Ok(apps)
    }

    /// Get application details
    pub async fn get_app(&self, name: &str) -> Result<Application> {
        let r = self.request(Method::GET, &format!("/appmesh/app/{}", name), None::<&Value>, None, None, true).await?;
        Ok(r.json().await?)
    }

    /// Get application output
    pub async fn get_app_output(
        &self,
        app: &str,
        stdout_position: i64,
        stdout_index: i32,
        stdout_maxsize: i32,
        process_uuid: Option<&str>,
        timeout: Option<i32>,
    ) -> Result<AppOutput> {
        let mut query = HashMap::new();
        if stdout_index > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_INDEX.to_string(), stdout_index.to_string());
        }
        if stdout_position > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_POSITION.to_string(), stdout_position.to_string());
        }
        if stdout_maxsize > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_MAXSIZE.to_string(), stdout_maxsize.to_string());
        }
        if let Some(uuid) = process_uuid {
            query.insert(HTTP_QUERY_KEY_PROCESS_UUID.to_string(), uuid.to_string());
        }
        if let Some(timeout) = timeout {
            query.insert(HTTP_QUERY_KEY_STDOUT_TIMEOUT.to_string(), timeout.to_string());
        }

        let resp = self
            .request(Method::GET, &format!("/appmesh/app/{}/output", app), None::<&Value>, None, Some(query), false)
            .await?;

        let mut out = AppOutput {
            status_code: resp.status().as_u16(),
            output: String::new(),
            output_position: 0,
            exit_code: None,
        };

        if let Some(pos) = resp.headers().get(HTTP_HEADER_KEY_OUTPUT_POS) {
            if let Ok(s) = pos.to_str() {
                out.output_position = s.parse().unwrap_or(0);
            }
        }

        if let Some(code) = resp.headers().get(HTTP_HEADER_KEY_EXIT_CODE) {
            if let Ok(s) = code.to_str() {
                out.exit_code = Some(s.parse().unwrap_or(0));
            }
        }

        out.output = resp.text().await?;

        Ok(out)
    }

    /// Check application health
    pub async fn check_app_health(&self, app: &str) -> Result<bool> {
        let r = self
            .request(Method::GET, &format!("/appmesh/app/{}/health", app), None::<&Value>, None, None, true)
            .await?;

        let text = r.text().await?;
        Ok(text.trim() == "0")
    }

    //
    // Application Manage
    //

    /// Add or update an application
    pub async fn add_app(&self, app: Value) -> Result<Application> {
        let name = app[JSON_KEY_APP_NAME]
            .as_str()
            .ok_or_else(|| AppMeshError::ConfigurationError("App name required".to_string()))?;

        let r = self.request(Method::PUT, &format!("/appmesh/app/{}", name), Some(&app), None, None, true).await?;
        Ok(r.json().await?)
    }

    /// Delete an application
    pub async fn delete_app(&self, name: &str) -> Result<bool> {
        let resp =
            self.request(Method::DELETE, &format!("/appmesh/app/{}", name), None::<&Value>, None, None, false).await?;

        Ok(resp.status() == StatusCode::OK)
    }

    /// Enable an application
    pub async fn enable_app(&self, name: &str) -> Result<()> {
        self.request(Method::POST, &format!("/appmesh/app/{}/enable", name), None::<&Value>, None, None, true).await?;
        Ok(())
    }

    /// Disable an application
    pub async fn disable_app(&self, name: &str) -> Result<()> {
        self.request(Method::POST, &format!("/appmesh/app/{}/disable", name), None::<&Value>, None, None, true).await?;
        Ok(())
    }

    //
    // Run Application Operations
    //

    /// Run application synchronously
    /// Returns (exit_code, output)
    pub async fn run_app_sync(&self, app: Value, max_timeout: i32, lifecycle: i32) -> Result<(Option<i32>, String)> {
        let mut query = HashMap::new();
        query.insert(HTTP_QUERY_KEY_TIMEOUT.to_string(), max_timeout.to_string());
        query.insert(HTTP_QUERY_KEY_LIFECYCLE.to_string(), lifecycle.to_string());

        let resp = self.request(Method::POST, "/appmesh/app/syncrun", Some(&app), None, Some(query), false).await?;

        let mut code = None;
        if resp.status() == StatusCode::OK {
            if let Some(h) = resp.headers().get(HTTP_HEADER_KEY_EXIT_CODE) {
                if let Ok(s) = h.to_str() {
                    code = Some(s.parse().unwrap_or(0));
                }
            }
        }

        let output = resp.text().await?;
        Ok((code, output))
    }

    /// Run application asynchronously
    pub async fn run_app_async(self: &Arc<Self>, app: Value, max_timeout: i32, lifecycle: i32) -> Result<AppRun> {
        let mut query = HashMap::new();
        query.insert(HTTP_QUERY_KEY_TIMEOUT.to_string(), max_timeout.to_string());
        query.insert(HTTP_QUERY_KEY_LIFECYCLE.to_string(), lifecycle.to_string());

        let r = self.request(Method::POST, "/appmesh/app/run", Some(&app), None, Some(query), true).await?;

        let json: Value = r.json().await?;
        Ok(AppRun {
            client: Arc::clone(self),
            app_name: json[JSON_KEY_APP_NAME]
                .as_str()
                .ok_or_else(|| AppMeshError::Other("Missing app name".to_string()))?
                .to_string(),
            proc_uid: json[JSON_KEY_PROCESS_UUID]
                .as_str()
                .ok_or_else(|| AppMeshError::Other("Missing process UUID".to_string()))?
                .to_string(),
        })
    }

    /// Wait for async run to complete
    pub async fn wait_for_async_run(&self, run: &AppRun, timeout: i32, print_to_std: bool) -> Result<Option<i32>> {
        let mut last_output_position = 0i64;
        let start_time = std::time::Instant::now();

        loop {
            let response = self
                .get_app_output(&run.app_name, last_output_position, 0, 10240, Some(&run.proc_uid), Some(1))
                .await?;

            last_output_position = response.output_position;

            if print_to_std && !response.output.is_empty() {
                print!("{}", response.output);
                use std::io::Write;
                std::io::stdout().flush().ok();
            }

            if response.exit_code.is_some()
                || response.status_code != StatusCode::OK.as_u16()
                || (timeout > 0 && start_time.elapsed().as_secs() >= timeout as u64)
            {
                // Clean up the temporary app
                let _ = self.delete_app(&run.app_name).await;
                return Ok(response.exit_code);
            }

            // Small delay before next poll
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Run a task
    pub async fn run_task(&self, app: &str, data: Value, timeout: i32) -> Result<String> {
        let mut query = HashMap::new();
        query.insert(HTTP_QUERY_KEY_TIMEOUT.to_string(), timeout.to_string());

        let r = self
            .request(Method::POST, &format!("/appmesh/app/{}/task", app), Some(&data), None, Some(query), true)
            .await?;

        Ok(r.text().await?)
    }

    /// Cancel a running task
    pub async fn cancel_task(&self, app: &str) -> Result<bool> {
        let r = self
            .request(Method::DELETE, &format!("/appmesh/app/{}/task", app), None::<&Value>, None, None, false)
            .await?;

        Ok(r.status() == StatusCode::OK)
    }

    //
    // System Management
    //

    /// Get host resource information
    pub async fn get_host_resources(&self) -> Result<serde_json::Value> {
        let r = self.request(Method::GET, "/appmesh/resources", None::<&Value>, None, None, true).await?;
        Ok(r.json().await?)
    }

    /// Get system configuration
    pub async fn get_config(&self) -> Result<Value> {
        let r = self.request(Method::GET, "/appmesh/config", None::<&Value>, None, None, true).await?;
        Ok(r.json().await?)
    }

    /// Set system configuration
    pub async fn set_config(&self, config: Value) -> Result<Value> {
        let r = self.request(Method::POST, "/appmesh/config", Some(&config), None, None, true).await?;
        Ok(r.json().await?)
    }

    /// Set log level
    pub async fn set_log_level(&self, level: &str) -> Result<String> {
        let cfg = json!({
            JSON_KEY_BASE_CONFIG: {
                JSON_KEY_LOG_LEVEL: level
            }
        });

        let resp = self.set_config(cfg).await?;
        Ok(resp[JSON_KEY_BASE_CONFIG][JSON_KEY_LOG_LEVEL].as_str().unwrap_or(level).to_string())
    }

    /// Get Prometheus metrics
    pub async fn get_metrics(&self) -> Result<String> {
        let r = self.request(Method::GET, "/appmesh/metrics", None::<&Value>, None, None, true).await?;
        Ok(r.text().await?)
    }

    //
    // Tag Management
    //

    /// Get all tags
    pub async fn get_tags(&self) -> Result<Value> {
        let response = self.request(Method::GET, "/appmesh/labels", None::<&Value>, None, None, true).await?;
        Ok(response.json().await?)
    }

    /// Add a tag
    pub async fn add_tag(&self, tag: &str, value: &str) -> Result<()> {
        let mut query = HashMap::new();
        query.insert(HTTP_QUERY_KEY_VALUE.to_string(), value.to_string());

        self.request(Method::PUT, &format!("/appmesh/label/{}", tag), None::<&Value>, None, Some(query), true).await?;
        Ok(())
    }

    /// Delete a tag
    pub async fn delete_tag(&self, tag: &str) -> Result<()> {
        self.request(Method::DELETE, &format!("/appmesh/label/{}", tag), None::<&Value>, None, None, true).await?;
        Ok(())
    }

    //
    // File Management
    //

    /// Download a file from remote server
    pub async fn download_file(&self, remote_file: &str, local_file: &str, preserve_permissions: bool) -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.to_string(), remote_file.to_string());

        let resp =
            self.request(Method::GET, "/appmesh/file/download", None::<&Value>, Some(headers), None, true).await?;

        // Clone headers before consuming the response
        let resp_headers = resp.headers().clone();

        // Write file content
        let bytes = resp.bytes().await?;
        fs::write(local_file, bytes)?;

        // Apply file attributes on Unix systems
        #[cfg(unix)]
        if preserve_permissions {
            use std::os::unix::fs::PermissionsExt;

            if let Some(mode_str) = resp_headers.get(HTTP_HEADER_KEY_X_FILE_MODE) {
                if let Ok(mode_str) = mode_str.to_str() {
                    if let Ok(mode) = u32::from_str(mode_str) {
                        let _ = fs::set_permissions(local_file, fs::Permissions::from_mode(mode));
                    }
                }
            }

            // Set ownership if available
            if let (Some(uid_str), Some(gid_str)) =
                (resp_headers.get(HTTP_HEADER_KEY_X_FILE_USER), resp_headers.get(HTTP_HEADER_KEY_X_FILE_GROUP))
            {
                if let (Ok(uid_str), Ok(gid_str)) = (uid_str.to_str(), gid_str.to_str()) {
                    if let (Ok(uid), Ok(gid)) = (uid_str.parse::<u32>(), gid_str.parse::<u32>()) {
                        use std::os::unix::fs::chown;
                        let _ = chown(local_file, Some(uid), Some(gid));
                    }
                }
            }
        }

        Ok(())
    }

    /// Upload a file to remote server
    pub async fn upload_file(&self, local_file: &str, remote_file: &str, preserve_permissions: bool) -> Result<()> {
        let local_path = Path::new(local_file);
        if !local_path.exists() {
            return Err(AppMeshError::NotFound(format!("Local file not found: {}", local_file)));
        }

        let file_content = fs::read(local_file)?;
        let file_name = local_path.file_name().and_then(|n| n.to_str()).unwrap_or("file");

        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.to_string(), remote_file.to_string());

        // Add file attributes on Unix systems
        #[cfg(unix)]
        if preserve_permissions {
            use std::os::unix::fs::PermissionsExt;

            if let Ok(metadata) = fs::metadata(local_file) {
                let permissions = metadata.permissions();
                let mode = permissions.mode() & 0o777;
                headers.insert(HTTP_HEADER_KEY_X_FILE_MODE.to_string(), mode.to_string());

                // Get file ownership
                use std::os::unix::fs::MetadataExt;
                headers.insert(HTTP_HEADER_KEY_X_FILE_USER.to_string(), metadata.uid().to_string());
                headers.insert(HTTP_HEADER_KEY_X_FILE_GROUP.to_string(), metadata.gid().to_string());
            }
        }

        // Create multipart form
        let form = reqwest::multipart::Form::new().text("filename", file_name.to_string()).part(
            "file",
            reqwest::multipart::Part::bytes(file_content)
                .file_name(file_name.to_string())
                .mime_str("application/octet-stream")?,
        );

        let url = format!("{}/appmesh/file/upload", self.config.url);
        debug!("POST {} {}", "/appmesh/file/upload", url);

        // Add common headers
        let mut all_headers = headers;
        self.add_common_headers(&mut all_headers);

        let mut req = self.client.post(&url).multipart(form);

        for (k, v) in all_headers {
            req = req.header(k, v);
        }

        let resp = req.send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            error!("HTTP {} error: {}", status, text);
            return Err(AppMeshError::RequestFailed { status, message: text });
        }

        Ok(())
    }

    //
    // Protected / internal helpers
    //

    /// Core HTTP request wrapper
    async fn request<T: serde::Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.config.url, path);
        debug!("{} {} {}", method, path, url);

        let mut req = self.client.request(method.clone(), &url);

        // Add common headers (CSRF token, forwarding)
        let mut all_headers = headers.unwrap_or_default();
        self.add_common_headers(&mut all_headers);
        for (k, v) in all_headers {
            req = req.header(k, v);
        }

        if let Some(body) = body {
            req = req.json(body);
        }

        if let Some(query) = query {
            req = req.query(&query);
        }

        let resp = req.send().await?;

        if resp.headers().contains_key(reqwest::header::SET_COOKIE) {
            if let Some(pj) = &self.persistent_jar {
                if let Err(e) = pj.save() {
                    error!("Failed to save cookies: {}", e);
                }
            }
        }

        if fail_on_error && !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            error!("HTTP {} error: {}", status, text);
            return Err(AppMeshError::RequestFailed { status, message: text });
        }

        Ok(resp)
    }

    /// Get a cookie value by name
    fn get_cookie(&self, name: &str) -> Option<String> {
        let url = self.config.url.parse().ok()?;
        self.cookie_jar.cookies(&url).and_then(|header_value: HeaderValue| {
            let s = header_value.to_str().ok()?;
            s.split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with(&format!("{name}=")))
                .map(|s| s[name.len() + 1..].to_string())
        })
    }

    /// Add common headers
    fn add_common_headers(&self, headers: &mut HashMap<String, String>) {
        // User agent
        headers.entry(HTTP_HEADER_KEY_USER_AGENT.to_string()).or_insert_with(|| HTTP_USER_AGENT.to_string());

        // Forwarding host
        if let Some(forward_to) = &self.forward_to {
            let forward_host = if forward_to.contains(':') {
                forward_to.clone()
            } else {
                format!("{}:{}", forward_to, Self::parse_url_port(&self.config.url))
            };
            headers.insert(HTTP_HEADER_KEY_FORWARDING_HOST.to_string(), forward_host);
        }

        // CSRF token
        if let Some(csrf_token) = self.get_cookie(COOKIE_CSRF_TOKEN) {
            if !csrf_token.is_empty() && !headers.contains_key(HTTP_HEADER_NAME_CSRF_TOKEN) {
                headers.insert(HTTP_HEADER_NAME_CSRF_TOKEN.to_string(), csrf_token);
            }
        }
        /* else if let Some(access_token) = self.get_cookie(COOKIE_TOKEN) {
            if !access_token.is_empty() && !headers.contains_key(HTTP_HEADER_JWT_AUTHORIZATION) {
                headers.insert(
                    HTTP_HEADER_JWT_AUTHORIZATION.to_string(),
                    format!("{}{}", HTTP_HEADER_AUTH_BEARER, access_token),
                );
            }
        }*/
    }

    /// Parse port from URL
    fn parse_url_port(url: &str) -> String {
        if let Ok(parsed) = url.parse::<url::Url>() {
            if let Some(port) = parsed.port() {
                return port.to_string();
            }
        }
        String::new()
    }
}

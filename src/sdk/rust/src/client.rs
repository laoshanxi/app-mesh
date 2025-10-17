// client.rs

use std::collections::HashMap;
use std::time::Duration;
use reqwest::{Client as ReqwestClient, Method, StatusCode};
use serde_json::{json, Value};
use log::{debug, error};
use base64::Engine;

use crate::constants::*;
use crate::models::*;
use crate::error::AppMeshError;

type Result<T> = std::result::Result<T, AppMeshError>;

/// Main AppMesh client for interacting with the AppMesh service
pub struct Client {
    client: ReqwestClient,
    config: ClientConfig,
    forward_to: Option<String>,
}

impl Client {
    //
    // Session/Client initialization
    //
    
    /// Create a new AppMesh client with the given configuration
    pub fn new(config: ClientConfig) -> Result<Self> {
        let mut client_builder = ReqwestClient::builder()
            .cookie_store(true)
            .timeout(Duration::from_secs(30));

        // SSL setup
        if let Some(ssl_verify) = &config.ssl_verify {
            let cert_bytes = std::fs::read(ssl_verify)?;
            client_builder = client_builder.add_root_certificate(
                reqwest::Certificate::from_pem(&cert_bytes)?
            );
        }

        if let (Some(cert), Some(key)) = (&config.ssl_client_cert, &config.ssl_client_key) {
            let cert_content = std::fs::read_to_string(cert)?;
            let key_content = std::fs::read_to_string(key)?;
            let pem = format!("{}\n{}", cert_content, key_content);
            let identity = reqwest::Identity::from_pem(pem.as_bytes())
                .map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
            client_builder = client_builder.identity(identity);
        }

        Ok(Self {
            client: client_builder.build()?,
            config,
            forward_to: None,
        })
    }

    /// Set forwarding host for requests
    pub fn forward_to(&mut self, url: Option<String>) {
        self.forward_to = url;
    }

    /// Core HTTP request wrapper
    async fn request<T: serde::Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        should_throw: bool,
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

        if should_throw && !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            error!("HTTP {} error: {}", status, text);
            return Err(AppMeshError::RequestFailed { status, message: text });
        }

        Ok(resp)
    }

    /// Add common headers like CSRF token and forwarding host
    fn add_common_headers(&self, headers: &mut HashMap<String, String>) {
        if let Some(forward_to) = &self.forward_to {
            let forward_host = if forward_to.contains(':') {
                forward_to.clone()
            } else {
                format!("{}:{}", forward_to, Self::parse_url_port(&self.config.url))
            };
            headers.insert(HTTP_HEADER_KEY_FORWARDING_HOST.to_string(), forward_host);
        }

        // In a real implementation, you would retrieve the CSRF token from cookies
        // For now, this is a placeholder
        // let csrf_token = self.get_csrf_token();
        // if !csrf_token.is_empty() {
        //     headers.insert(HTTP_HEADER_NAME_CSRF_TOKEN.to_string(), csrf_token);
        // }
    }

    /// Parse port from URL
    fn parse_url_port(url: &str) -> String {
        use regex::Regex;
        let re = Regex::new(r"^(?:https?://)?(?:\[[^\]]+\]|[^/:?#]+):([0-9]+)").unwrap();
        if let Some(caps) = re.captures(url) {
            return caps.get(1).map_or("", |m| m.as_str()).to_string();
        }
        String::new()
    }

    //
    // Authentication Management
    //
    
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

        let response = self.request(
            Method::POST,
            "/appmesh/login",
            Option::<&Value>::None,
            Some(headers),
            None,
            false,
        ).await?;

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

    pub async fn validate_totp(
        &self,
        username: &str,
        challenge: &str,
        totp: &str,
        timeout_seconds: i32,
    ) -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_JWT_SET_COOKIE.to_string(), "true".to_string());

        let body = json!({
            HTTP_BODY_KEY_JWT_USERNAME: username,
            HTTP_BODY_KEY_JWT_TOTP: totp,
            HTTP_BODY_KEY_JWT_TOTP_CHALLENGE: challenge,
            HTTP_BODY_KEY_JWT_EXPIRE_SECONDS: timeout_seconds
        });

        self.request(Method::POST, "/appmesh/totp/validate", Some(&body), Some(headers), None, true)
            .await?;
        Ok(())
    }

    pub async fn authenticate(
        &self,
        token: &str,
        permission: Option<&str>,
        audience: Option<&str>,
        apply: bool,
    ) -> Result<(bool, String)> {
        let mut headers = HashMap::new();
        headers.insert(
            HTTP_HEADER_JWT_AUTHORIZATION.to_string(),
            format!("{}{}", HTTP_HEADER_AUTH_BEARER, token),
        );

        if let Some(perm) = permission {
            headers.insert(HTTP_HEADER_JWT_AUTH_PERMISSION.to_string(), perm.to_string());
        }
        if let Some(aud) = audience {
            headers.insert(HTTP_HEADER_JWT_AUDIENCE.to_string(), aud.to_string());
        }
        if apply {
            headers.insert(HTTP_HEADER_JWT_SET_COOKIE.to_string(), "true".to_string());
        }

        let resp = self.request(
            Method::POST,
            "/appmesh/auth",
            None::<&Value>,
            Some(headers),
            None,
            false,
        ).await?;
        
        let is_ok = resp.status() == StatusCode::OK;
        let text = resp.text().await?;
        Ok((is_ok, text))
    }

    pub async fn logout(&self) -> Result<()> {
        self.request(
            Method::POST,
            "/appmesh/self/logoff",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn renew_token(&self, timeout_seconds: Option<i32>) -> Result<()> {
        let mut headers = HashMap::new();
        if let Some(sec) = timeout_seconds {
            headers.insert(HTTP_HEADER_JWT_EXPIRE_SECONDS.to_string(), sec.to_string());
        }

        self.request(
            Method::POST,
            "/appmesh/token/renew",
            None::<&Value>,
            Some(headers),
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn get_totp_secret(&self) -> Result<String> {
        let resp = self.request(
            Method::POST,
            "/appmesh/totp/secret",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        
        let val: Value = resp.json().await?;
        let encoded = val[HTTP_BODY_KEY_MFA_URI]
            .as_str()
            .ok_or_else(|| AppMeshError::Other("Invalid MFA URI".to_string()))?;
        
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        Ok(String::from_utf8_lossy(&decoded).to_string())
    }

    pub async fn enable_totp(&self, totp: &str) -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_JWT_TOTP.to_string(), totp.to_string());
        
        self.request(
            Method::POST,
            "/appmesh/totp/setup",
            None::<&Value>,
            Some(headers),
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn disable_totp(&self, user: Option<&str>) -> Result<()> {
        let user = user.unwrap_or("self");
        self.request(
            Method::POST,
            &format!("/appmesh/totp/{}/disable", user),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    //
    // User Management
    //

    pub async fn update_password(&self, old: &str, new: &str, user: Option<&str>) -> Result<()> {
        let user = user.unwrap_or("self");
        let body = json!({
            HTTP_BODY_KEY_OLD_PASSWORD: base64::engine::general_purpose::STANDARD.encode(old),
            HTTP_BODY_KEY_NEW_PASSWORD: base64::engine::general_purpose::STANDARD.encode(new)
        });
        
        self.request(
            Method::POST,
            &format!("/appmesh/user/{}/passwd", user),
            Some(&body),
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn get_current_user(&self) -> Result<Value> {
        let r = self.request(
            Method::GET,
            "/appmesh/user/self",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(r.json().await?)
    }

    pub async fn list_users(&self) -> Result<Value> {
        let r = self.request(
            Method::GET,
            "/appmesh/users",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(r.json().await?)
    }

    pub async fn add_user(&self, user: Value) -> Result<()> {
        let name = user["name"]
            .as_str()
            .ok_or_else(|| AppMeshError::ConfigurationError("Missing username".to_string()))?;
        
        self.request(
            Method::PUT,
            &format!("/appmesh/user/{}", name),
            Some(&user),
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn delete_user(&self, user: &str) -> Result<()> {
        self.request(
            Method::DELETE,
            &format!("/appmesh/user/{}", user),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn lock_user(&self, user: &str) -> Result<()> {
        self.request(
            Method::POST,
            &format!("/appmesh/user/{}/lock", user),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn unlock_user(&self, user: &str) -> Result<()> {
        self.request(
            Method::POST,
            &format!("/appmesh/user/{}/unlock", user),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn list_groups(&self) -> Result<Vec<String>> {
        let r = self.request(
            Method::GET,
            "/appmesh/user/groups",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        
        let json: Value = r.json().await?;
        Ok(json
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
    }

    pub async fn get_user_permissions(&self) -> Result<Vec<String>> {
        let r = self.request(
            Method::GET,
            "/appmesh/user/permissions",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        
        let json: Value = r.json().await?;
        Ok(json
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
    }

    pub async fn list_permissions(&self) -> Result<Vec<String>> {
        let r = self.request(
            Method::GET,
            "/appmesh/permissions",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        
        let json: Value = r.json().await?;
        Ok(json
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
    }

    pub async fn list_roles(&self) -> Result<HashMap<String, Vec<String>>> {
        let r = self.request(
            Method::GET,
            "/appmesh/roles",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        
        let json: Value = r.json().await?;
        let mut roles = HashMap::new();
        
        if let Some(obj) = json.as_object() {
            for (key, value) in obj {
                if let Some(arr) = value.as_array() {
                    let perms: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    roles.insert(key.clone(), perms);
                }
            }
        }
        
        Ok(roles)
    }

    pub async fn update_role(&self, role: &str, permissions: Vec<String>) -> Result<()> {
        let body = json!(permissions);
        
        self.request(
            Method::POST,
            &format!("/appmesh/role/{}", role),
            Some(&body),
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn delete_role(&self, role: &str) -> Result<()> {
        self.request(
            Method::DELETE,
            &format!("/appmesh/role/{}", role),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    //
    // Application Management
    //

    pub async fn list_apps(&self) -> Result<Vec<Application>> {
        let r = self.request(
            Method::GET,
            "/appmesh/applications",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(r.json().await?)
    }

    pub async fn get_app(&self, name: &str) -> Result<Application> {
        let r = self.request(
            Method::GET,
            &format!("/appmesh/app/{}", name),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(r.json().await?)
    }

    pub async fn add_app(&self, app: Value) -> Result<Application> {
        let name = app[JSON_KEY_APP_NAME]
            .as_str()
            .ok_or_else(|| AppMeshError::ConfigurationError("App name required".to_string()))?;
        
        let r = self.request(
            Method::PUT,
            &format!("/appmesh/app/{}", name),
            Some(&app),
            None,
            None,
            true,
        ).await?;
        Ok(r.json().await?)
    }

    pub async fn delete_app(&self, name: &str) -> Result<()> {
        self.request(
            Method::DELETE,
            &format!("/appmesh/app/{}", name),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn enable_app(&self, name: &str) -> Result<()> {
        self.request(
            Method::POST,
            &format!("/appmesh/app/{}/enable", name),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn disable_app(&self, name: &str) -> Result<()> {
        self.request(
            Method::POST,
            &format!("/appmesh/app/{}/disable", name),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }

    pub async fn get_app_output(
        &self,
        app: &str,
        position: i64,
        index: i32,
        maxsize: i32,
        uuid: Option<&str>,
        timeout: Option<i32>,
    ) -> Result<AppOutput> {
        let mut query = HashMap::new();
        if index > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_INDEX.to_string(), index.to_string());
        }
        if position > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_POSITION.to_string(), position.to_string());
        }
        if maxsize > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_MAXSIZE.to_string(), maxsize.to_string());
        }
        if let Some(uuid) = uuid {
            query.insert(HTTP_QUERY_KEY_PROCESS_UUID.to_string(), uuid.to_string());
        }
        if let Some(timeout) = timeout {
            query.insert(HTTP_QUERY_KEY_STDOUT_TIMEOUT.to_string(), timeout.to_string());
        }

        let resp = self.request(
            Method::GET,
            &format!("/appmesh/app/{}/output", app),
            None::<&Value>,
            None,
            Some(query),
            true,
        ).await?;

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

    pub async fn check_app_health(&self, app: &str) -> Result<bool> {
        let r = self.request(
            Method::GET,
            &format!("/appmesh/app/{}/health", app),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        
        let text = r.text().await?;
        Ok(text.trim() == "0")
    }

    //
    // Run Application Operations
    //

    pub async fn run_app_sync(
        &self,
        app: Value,
        max_timeout: i32,
        lifecycle: i32,
    ) -> Result<(Option<i32>, String)> {
        let mut query = HashMap::new();
        query.insert(HTTP_QUERY_KEY_TIMEOUT.to_string(), max_timeout.abs().to_string());
        query.insert(HTTP_QUERY_KEY_LIFECYCLE.to_string(), lifecycle.abs().to_string());

        let resp = self.request(
            Method::POST,
            "/appmesh/app/syncrun",
            Some(&app),
            None,
            Some(query),
            true,
        ).await?;

        let mut code = None;
        if let Some(h) = resp.headers().get(HTTP_HEADER_KEY_EXIT_CODE) {
            if let Ok(s) = h.to_str() {
                code = Some(s.parse().unwrap_or(0));
            }
        }

        let output = resp.text().await?;
        Ok((code, output))
    }

    pub async fn run_app_async(
        &self,
        app: Value,
        max_timeout: i32,
        lifecycle: i32,
    ) -> Result<AppRun> {
        let mut query = HashMap::new();
        query.insert(HTTP_QUERY_KEY_TIMEOUT.to_string(), max_timeout.to_string());
        query.insert(HTTP_QUERY_KEY_LIFECYCLE.to_string(), lifecycle.to_string());

        let r = self.request(
            Method::POST,
            "/appmesh/app/run",
            Some(&app),
            None,
            Some(query),
            true,
        ).await?;
        
        let json: Value = r.json().await?;
        Ok(AppRun {
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

    pub async fn wait_for_async_run(
        &self,
        run: &AppRun,
        timeout: i32,
        print_to_std: bool,
    ) -> Result<Option<i32>> {
        let mut last_output_position = 0i64;
        let start_time = std::time::Instant::now();

        loop {
            let response = self.get_app_output(
                &run.app_name,
                last_output_position,
                0,
                10240,
                Some(&run.proc_uid),
                Some(timeout),
            ).await?;

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
                return Ok(response.exit_code);
            }

            // Small delay before next poll
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn run_task(
        &self,
        app: &str,
        data: Value,
        timeout: i32,
    ) -> Result<String> {
        let mut query = HashMap::new();
        query.insert("timeout".to_string(), timeout.to_string());

        let r = self.request(
            Method::POST,
            &format!("/appmesh/app/{}/task", app),
            Some(&data),
            None,
            Some(query),
            true,
        ).await?;
        
        Ok(r.text().await?)
    }

    pub async fn cancel_task(&self, app: &str) -> Result<bool> {
        let r = self.request(
            Method::DELETE,
            &format!("/appmesh/app/{}/task", app),
            None::<&Value>,
            None,
            None,
            false,
        ).await?;
        
        Ok(r.status() == StatusCode::OK)
    }

    //
    // System Management
    //

    pub async fn get_host_resources(&self) -> Result<HostResource> {
        let r = self.request(
            Method::GET,
            "/appmesh/resources",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(r.json().await?)
    }

    pub async fn get_config(&self) -> Result<Value> {
        let r = self.request(
            Method::GET,
            "/appmesh/config",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(r.json().await?)
    }

    pub async fn set_config(&self, config: Value) -> Result<Value> {
        let r = self.request(
            Method::POST,
            "/appmesh/config",
            Some(&config),
            None,
            None,
            true,
        ).await?;
        Ok(r.json().await?)
    }

    pub async fn set_log_level(&self, level: &str) -> Result<String> {
        let cfg = json!({
            JSON_KEY_BASE_CONFIG: {
                JSON_KEY_LOG_LEVEL: level
            }
        });
        
        let resp = self.set_config(cfg).await?;
        Ok(resp[JSON_KEY_BASE_CONFIG][JSON_KEY_LOG_LEVEL]
            .as_str()
            .unwrap_or(level)
            .to_string())
    }

    pub async fn get_metrics(&self) -> Result<String> {
        let r = self.request(
            Method::GET,
            "/appmesh/metrics",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(r.text().await?)
    }

    //
    // Tag Management
    //

    pub async fn get_tags(&self) -> Result<Value> {
        let response = self.request(
            Method::GET,
            "/appmesh/labels",
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(response.json().await?)
    }

    pub async fn add_tag(&self, tag: &str, value: &str) -> Result<()> {
        let mut query = HashMap::new();
        query.insert("value".to_string(), value.to_string());

        self.request(
            Method::PUT,
            &format!("/appmesh/label/{}", tag),
            None::<&Value>,
            None,
            Some(query),
            true,
        ).await?;
        Ok(())
    }

    pub async fn delete_tag(&self, tag: &str) -> Result<()> {
        self.request(
            Method::DELETE,
            &format!("/appmesh/label/{}", tag),
            None::<&Value>,
            None,
            None,
            true,
        ).await?;
        Ok(())
    }
}
use std::collections::HashMap;
use std::time::Duration;
use anyhow::{anyhow, Result};
use reqwest::{Client as ReqwestClient, Method, StatusCode};
use serde_json::{json, Value};
use log::{debug, error};
use base64::Engine;

use crate::constants::*;
use crate::models::*;

use crate::models::{AppOutput, AppRun, ClientConfig};
use crate::error::AppMeshError;

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
            client_builder = client_builder.add_root_certificate(reqwest::Certificate::from_pem(&cert_bytes)?);
        }

        if let (Some(cert), Some(key)) = (&config.ssl_client_cert, &config.ssl_client_key) {
            let pem = format!("{}\n{}", std::fs::read_to_string(cert)?, std::fs::read_to_string(key)?);
            let identity = reqwest::Identity::from_pem(pem.as_bytes())?;
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
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.config.url, path);
        debug!("{} {}", method, url);

        let mut req = self.client.request(method, &url);

        if let Some(hdrs) = headers {
            for (k, v) in hdrs {
                req = req.header(k, v);
            }
        }

        if let Some(body) = body {
            req = req.json(body);
        }

        if let Some(query) = query {
            req = req.query(&query);
        }

        if let Some(forward_to) = &self.forward_to {
            req = req.header("X-Forwarding-Host", forward_to);
        }

        let resp = req.send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            error!("HTTP {} error: {}", status, text);
            return Err(AppMeshError::RequestFailed { status, message: text }.into());
        }

        Ok(resp)
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
            format!("{}{}", HTTP_HEADER_AUTH_BASIC, base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password))),
        );
        headers.insert(HTTP_HEADER_JWT_SET_COOKIE.to_string(), "true".into());

        if let Some(seconds) = timeout_seconds {
            headers.insert(HTTP_HEADER_JWT_EXPIRE_SECONDS.to_string(), seconds.to_string());
        }
        if let Some(aud) = audience {
            headers.insert(HTTP_HEADER_JWT_AUDIENCE.to_string(), aud.to_string());
        }
        if let Some(totp_code) = totp {
            headers.insert(HTTP_HEADER_JWT_TOTP.to_string(), totp_code.to_string());
        }

        let response = self.request(Method::POST, "/appmesh/login", Option::<&Value>::None, Some(headers), None)
            .await?;

        // Handle TOTP challenge (HTTP 428)
        if response.status() == StatusCode::PRECONDITION_REQUIRED {
            let json: Value = response.json().await?;
            if let Some(challenge) = json.get("totp_challenge") {
                return Ok(challenge.as_str().unwrap().to_string());
            }
        } else if response.status() != StatusCode::OK {
            return Err(anyhow!(response.text().await?));
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
        headers.insert(HTTP_HEADER_JWT_SET_COOKIE.to_string(), "true".into());

        let body = json!({
            HTTP_BODY_KEY_JWT_USERNAME: username,
            HTTP_BODY_KEY_JWT_TOTP: totp,
            HTTP_BODY_KEY_JWT_TOTP_CHALLENGE: challenge,
            HTTP_BODY_KEY_JWT_EXPIRE_SECONDS: timeout_seconds
        });

        self.request(Method::POST, "/appmesh/totp/validate", Some(&body), Some(headers), None)
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
            headers.insert(HTTP_HEADER_JWT_AUTH_PERMISSION.to_string(), perm.into());
        }
        if let Some(aud) = audience {
            headers.insert(HTTP_HEADER_JWT_AUDIENCE.to_string(), aud.into());
        }
        if apply {
            headers.insert(HTTP_HEADER_JWT_SET_COOKIE.to_string(), "true".into());
        }

        let resp = self
            .request(Method::POST, "/appmesh/auth", None::<&Value>, Some(headers), None)
            .await?;
        Ok((resp.status() == StatusCode::OK, resp.text().await?))
    }

    pub async fn logout(&self) -> Result<()> {
        self.request(Method::POST, "/appmesh/self/logoff", None::<&Value>, None, None)
            .await?;
        Ok(())
    }

    pub async fn renew_token(&self, timeout_seconds: Option<i32>) -> Result<()> {
        let mut headers = HashMap::new();
        if let Some(sec) = timeout_seconds {
            headers.insert(HTTP_HEADER_JWT_EXPIRE_SECONDS.to_string(), sec.to_string());
        }

        self.request(Method::POST, "/appmesh/token/renew", None::<&Value>, Some(headers), None)
            .await?;
        Ok(())
    }

    pub async fn get_totp_secret(&self) -> Result<String> {
        let resp = self.request(
            Method::POST, "/appmesh/totp/secret", None::<&Value>, None, None
        ).await?;
        let val: Value = resp.json().await?;
        Ok(base64::engine::general_purpose::STANDARD.decode(
            val[HTTP_BODY_KEY_MFA_URI]
                .as_str()
                .ok_or_else(|| anyhow!("Invalid MFA URI"))?,
        )?
        .iter()
        .map(|b| *b as char)
        .collect())
    }

    pub async fn enable_totp(&self, totp: &str) -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_JWT_TOTP.to_string(), totp.into());
        self.request(
            Method::POST, "/appmesh/totp/setup", None::<&Value>, Some(headers), None
        ).await?;
        Ok(())
    }

    pub async fn disable_totp(&self, user: Option<&str>) -> Result<()> {
        let user = user.unwrap_or("self");
        self.request(
            Method::POST, &format!("/appmesh/totp/{}/disable", user), None::<&Value>, None, None
        ).await?;
        Ok(())
    }

    // === USERS ===

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
        ).await?;
        Ok(())
    }

    pub async fn get_current_user(&self) -> Result<Value> {
        let r = self.request(Method::GET, "/appmesh/user/self", None::<&Value>, None, None).await?;
        Ok(r.json().await?)
    }

    pub async fn list_users(&self) -> Result<Value> {
        let r = self.request(Method::GET, "/appmesh/users", None::<&Value>, None, None).await?;
        Ok(r.json().await?)
    }

    pub async fn add_user(&self, user: Value) -> Result<()> {
        let name = user["name"].as_str().ok_or_else(|| anyhow!("Missing username"))?;
        self.request(Method::PUT, &format!("/appmesh/user/{}", name), Some(&user), None, None)
            .await?;
        Ok(())
    }

    pub async fn delete_user(&self, user: &str) -> Result<()> {
        self.request(Method::DELETE, &format!("/appmesh/user/{}", user), None::<&Value>, None, None)
            .await?;
        Ok(())
    }

    pub async fn lock_user(&self, user: &str) -> Result<()> {
        self.request(Method::POST, &format!("/appmesh/user/{}/lock", user), None::<&Value>, None, None)
            .await?;
        Ok(())
    }

    pub async fn unlock_user(&self, user: &str) -> Result<()> {
        self.request(Method::POST, &format!("/appmesh/user/{}/unlock", user), None::<&Value>, None, None)
            .await?;
        Ok(())
    }

    pub async fn list_groups(&self) -> Result<Vec<String>> {
        let r = self
            .request(Method::GET, "/appmesh/user/groups", None::<&Value>, None, None)
            .await?;
        let json: Value = r.json().await?;
        Ok(json
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
    }

    // === APPS ===

    pub async fn list_apps(&self) -> Result<Vec<Application>> {
        let r = self.request(Method::GET, "/appmesh/applications", None::<&Value>, None, None).await?;
        Ok(r.json().await?)
    }

    pub async fn get_app(&self, name: &str) -> Result<Application> {
        let r = self.request(Method::GET, &format!("/appmesh/app/{}", name), None::<&Value>, None, None).await?;
        Ok(r.json().await?)
    }

    pub async fn add_app(&self, app: Value) -> Result<Application> {
        let name = app["name"].as_str().ok_or_else(|| anyhow!("App name required"))?;
        let r = self.request(Method::PUT, &format!("/appmesh/app/{}", name), Some(&app), None, None).await?;
        Ok(r.json().await?)
    }

    pub async fn delete_app(&self, name: &str) -> Result<()> {
        self.request(Method::DELETE, &format!("/appmesh/app/{}", name), None::<&Value>, None, None).await?;
        Ok(())
    }

    pub async fn enable_app(&self, name: &str) -> Result<()> {
        self.request(Method::POST, &format!("/appmesh/app/{}/enable", name), None::<&Value>, None, None).await?;
        Ok(())
    }

    pub async fn disable_app(&self, name: &str) -> Result<()> {
        self.request(Method::POST, &format!("/appmesh/app/{}/disable", name), None::<&Value>, None, None).await?;
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
            query.insert(HTTP_QUERY_KEY_STDOUT_INDEX.into(), index.to_string());
        }
        if position > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_POSITION.into(), position.to_string());
        }
        if maxsize > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_MAXSIZE.into(), maxsize.to_string());
        }
        if let Some(uuid) = uuid {
            query.insert(HTTP_QUERY_KEY_PROCESS_UUID.into(), uuid.into());
        }
        if let Some(timeout) = timeout {
            query.insert(HTTP_QUERY_KEY_STDOUT_TIMEOUT.into(), timeout.to_string());
        }

        let resp = self
            .request(Method::GET, &format!("/appmesh/app/{}/output", app), None::<&Value>, None, Some(query))
            .await?;

        let mut out = AppOutput {
            status_code: resp.status().as_u16(),
            output: resp.text().await?,
            output_position: 0,
            exit_code: None,
        };

        if let Some(pos) = resp.headers().get("X-Output-Position") {
            if let Ok(s) = pos.to_str() {
                out.output_position = s.parse().unwrap_or(0);
            }
        }

        if let Some(code) = resp.headers().get("X-Exit-Code") {
            if let Ok(s) = code.to_str() {
                out.exit_code = Some(s.parse().unwrap_or(0));
            }
        }

        Ok(out)
    }

    pub async fn check_app_health(&self, app: &str) -> Result<bool> {
        let r = self.request(Method::GET, &format!("/appmesh/app/{}/health", app), None::<&Value>, None, None).await?;
        Ok(r.text().await?.trim() == "0")
    }

    //
    // Run Application Operations
    //

    pub async fn run_app_sync(&self, app: Value, max_timeout: i32, lifecycle: i32) -> Result<(Option<i32>, String)> {
        let mut query = HashMap::new();
        query.insert(HTTP_QUERY_KEY_TIMEOUT.into(), max_timeout.abs().to_string());
        query.insert(HTTP_QUERY_KEY_LIFECYCLE.into(), lifecycle.abs().to_string());

        let resp = self
            .request(Method::POST, "/appmesh/app/syncrun", Some(&app), None, Some(query))
            .await?;

        let mut code = None;
        if let Some(h) = resp.headers().get("X-Exit-Code") {
            if let Ok(s) = h.to_str() {
                code = Some(s.parse().unwrap_or(0));
            }
        }

        Ok((code, resp.text().await?))
    }

    pub async fn run_app_async(&self, app: Value, max_timeout: i32, lifecycle: i32) -> Result<AppRun<'_>> {
        let mut query = HashMap::new();
        query.insert(HTTP_QUERY_KEY_TIMEOUT.into(), max_timeout.to_string());
        query.insert(HTTP_QUERY_KEY_LIFECYCLE.into(), lifecycle.to_string());

        let r = self
            .request(Method::POST, "/appmesh/app/run", Some(&app), None, Some(query))
            .await?;
        let json: Value = r.json().await?;
        Ok(AppRun {
            client: self,
            app_name: json["name"].as_str().unwrap().to_string(),
            proc_uid: json["process_uuid"].as_str().unwrap().to_string(),
        })
    }

    //
    // System Management
    // 

    pub async fn get_host_resources(&self) -> Result<HostResource> {
        let r = self.request(Method::GET, "/appmesh/resources", None::<&Value>, None, None).await?;
        Ok(r.json().await?)
    }

    pub async fn get_config(&self) -> Result<Value> {
        let r = self.request(Method::GET, "/appmesh/config", None::<&Value>, None, None).await?;
        Ok(r.json().await?)
    }

    pub async fn set_config(&self, config: Value) -> Result<Value> {
        let r = self.request(Method::POST, "/appmesh/config", Some(&config), None, None).await?;
        Ok(r.json().await?)
    }

    pub async fn set_log_level(&self, level: &str) -> Result<String> {
        let cfg = json!({ "BaseConfig": { "LogLevel": level } });
        let resp = self.set_config(cfg).await?;
        Ok(resp["BaseConfig"]["LogLevel"].as_str().unwrap_or(level).to_string())
    }

    pub async fn get_metrics(&self) -> Result<String> {
        let r = self.request(Method::GET, "/appmesh/metrics", None::<&Value>, None, None).await?;
        Ok(r.text().await?)
    }

    // Tag Management
    pub async fn get_tags(&self) -> Result<Value> {
        let response = self.request(Method::GET, "/appmesh/labels", None::<&Value>, None, None).await?;
        Ok(response.json().await?)
    }

    pub async fn add_tag(&self, tag: &str, value: &str) -> Result<()> {
        let mut query = HashMap::new();
        query.insert("value".to_string(), value.to_string());

        self.request(Method::PUT, &format!("/appmesh/label/{}", tag), None::<&Value>, None, Some(query)).await?;
        Ok(())
    }

    pub async fn delete_tag(&self, tag: &str) -> Result<()> {
        self.request(Method::DELETE, &format!("/appmesh/label/{}", tag), None::<&Value>, None, None).await?;
        Ok(())
    }
}

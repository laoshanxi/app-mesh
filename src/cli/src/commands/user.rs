use anyhow::{Context, Result};

use crate::app::{Cli, LockArgs, MfaArgs, PasswdArgs, UserArgs};
use crate::client::build_client_with_auth;
use crate::output::format;
use crate::util::{config, confirm, password};

pub async fn passwd(cli: &Cli, args: &PasswdArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let old_pass = password::prompt_password("Current password: ")?;
    let new_pass = password::prompt_password("New password: ")?;
    let confirm_pass = password::prompt_password("Confirm new password: ")?;

    if new_pass != confirm_pass {
        eprintln!("Passwords do not match.");
        return Ok(1);
    }

    let target = args.target.as_deref();
    client
        .update_password(&old_pass, &new_pass, target)
        .await
        .context("Failed to update password")?;

    eprintln!("Password changed successfully.");
    Ok(0)
}

pub async fn lock(cli: &Cli, args: &LockArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    if args.lock {
        client
            .lock_user(&args.target)
            .await
            .context("Failed to lock user")?;
        eprintln!("User <{}> locked successfully.", args.target);
    } else {
        client
            .unlock_user(&args.target)
            .await
            .context("Failed to unlock user")?;
        eprintln!("User <{}> unlocked successfully.", args.target);
    }
    Ok(0)
}

pub async fn user(cli: &Cli, args: &UserArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    if let Some(ref json_path) = args.json {
        let content = std::fs::read_to_string(json_path).context("Failed to read user JSON")?;
        let mut user_data: serde_json::Value =
            serde_json::from_str(&content).context("Invalid JSON")?;

        let name = user_data["name"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        if !args.force
            && !confirm::confirm(&format!(
                "Confirm to register user <{}> ? [y/n]:",
                name
            ))
        {
            return Ok(0);
        }

        // Prompt for the password if not in JSON. The server reads the password
        // from the "key" field (JSON_KEY_USER_key), not "password".
        if user_data.get("key").is_none() || user_data["key"].is_null() {
            let pwd = password::prompt_password(&format!("Password for user '{}': ", name))?;
            user_data["key"] = serde_json::Value::String(pwd);
        }

        client
            .add_user(user_data)
            .await
            .context("Failed to add user")?;
        eprintln!("User <{}> registered successfully.", name);
        return Ok(0);
    }

    if args.all {
        let users = client.list_users().await.context("Failed to list users")?;
        format::print_json(&users)?;
        return Ok(0);
    }

    // Default: show current user with ext paths embedded in JSON (matching C++)
    let mut info = client
        .get_current_user()
        .await
        .context("Failed to get user info")?;

    // Embed local ext paths into the JSON response (C++ behavior)
    if let Some(obj) = info.as_object_mut() {
        if !obj.contains_key("ext") {
            obj.insert("ext".to_string(), serde_json::json!({}));
        }
        if let Some(ext) = obj.get_mut("ext").and_then(|v| v.as_object_mut()) {
            ext.insert(
                "config".to_string(),
                serde_json::Value::String(
                    config::config_dir()
                        .join(".appmesh.config")
                        .to_string_lossy()
                        .to_string(),
                ),
            );
            ext.insert(
                "history".to_string(),
                serde_json::Value::String(
                    config::shell_history_path().to_string_lossy().to_string(),
                ),
            );
        }
    }

    format::print_json(&info)?;
    Ok(0)
}

pub async fn mfa(cli: &Cli, args: &MfaArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    if args.add {
        // The CLI shows the raw secret for manual authenticator entry.
        let secret = client
            .get_totp_secret()
            .await
            .context("Failed to get TOTP secret")?;
        println!("TOTP Secret: {}", secret);
        println!("Add this secret to your authenticator app, then enter the code below.");

        // Loop until TOTP validates (matching C++ behavior)
        loop {
            let totp_code = password::prompt_totp()?;
            if totp_code.is_empty() {
                eprintln!("Cancelled.");
                return Ok(1);
            }
            match client.enable_totp(&totp_code).await {
                Ok(()) => {
                    eprintln!("TOTP setup successful.");
                    return Ok(0);
                }
                Err(_) => {
                    // C++ silently retries; print minimal feedback
                    eprint!("Invalid code, try again: ");
                    std::io::Write::flush(&mut std::io::stderr()).ok();
                }
            }
        }
    }

    if args.delete {
        client
            .disable_totp(None)
            .await
            .context("Failed to disable TOTP")?;
        eprintln!("2FA deactivated successfully.");
        return Ok(0);
    }

    eprintln!("Use --add to enable MFA or --delete to disable it.");
    Ok(1)
}

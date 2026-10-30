use anyhow::{bail, Context, Result};

use crate::app::{Cli, LabelArgs, LogArgs};
use crate::client::build_client_with_auth;
use crate::output::format;

pub async fn label(cli: &Cli, args: &LabelArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    if args.add {
        for lbl in &args.label {
            let (key, value) = lbl
                .split_once('=')
                .filter(|(key, _)| !key.is_empty())
                .with_context(|| format!("Invalid label '{lbl}': expected <key>=<value> with a non-empty key"))?;
            client.add_label(key, value).await.context("Failed to add label")?;
        }
    } else if args.delete {
        for lbl in &args.label {
            let key = lbl.split('=').next().unwrap_or(lbl);
            if key.is_empty() {
                bail!("Invalid label '{lbl}': expected a non-empty key");
            }
            client.delete_label(key).await.context("Failed to delete label")?;
        }
    }

    // Always print the resulting labels (C++ prints labels after add/delete/view).
    let labels = client.list_labels().await.context("Failed to list labels")?;
    if let Some(obj) = labels.as_object() {
        for (k, v) in obj {
            println!("{}={}", k, v.as_str().unwrap_or(&v.to_string()));
        }
    } else {
        format::print_json(&labels)?;
    }
    Ok(0)
}

pub async fn log_level(cli: &Cli, args: &LogArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;

    let valid_levels = ["DEBUG", "INFO", "NOTICE", "WARN", "ERROR"];
    let level = args.level.to_uppercase();
    if !valid_levels.contains(&level.as_str()) {
        bail!("Invalid log level '{}'. Valid: {:?}", args.level, valid_levels);
    }

    let result = client.set_log_level(&level).await.context("Failed to set log level")?;
    eprintln!("Log level set to: {}", result);
    Ok(0)
}

pub async fn config(cli: &Cli) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let cfg = client.get_config().await.context("Failed to get config")?;
    format::print_json(&cfg)?;
    Ok(0)
}

pub async fn resource(cli: &Cli) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let res = client.get_host_resources().await.context("Failed to get resources")?;
    format::print_json(&res)?;
    Ok(0)
}

pub async fn metric(cli: &Cli) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let metrics = client.get_metrics().await.context("Failed to get metrics")?;
    print!("{}", metrics);
    Ok(0)
}

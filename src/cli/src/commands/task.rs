use anyhow::{Context, Result};
use std::sync::Arc;

use appmesh::AppMeshClientWSS;

use crate::app::{Cli, TaskArgs};
use crate::client::build_client_with_auth;
use crate::util::parse;

pub async fn task(cli: &Cli, args: &TaskArgs) -> Result<i32> {
    let client: Arc<AppMeshClientWSS> = build_client_with_auth(cli).await?;

    let payload = args.payload.as_deref().unwrap_or("");
    let payload =
        if payload.is_empty() { serde_json::Value::String(String::new()) } else { parse::parse_metadata(payload)? };

    let response = client
        .client()
        .run_task(&args.app, payload, args.timeout)
        .await
        .with_context(|| format!("Task for '{}' failed", args.app))?;
    if !response.is_empty() {
        println!("{}", response);
    }
    Ok(0)
}

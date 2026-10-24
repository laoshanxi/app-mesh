use std::sync::Arc;

use anyhow::{bail, Result};
use serde_json::json;

use crate::app::{
    Cli, WorkflowAddArgs, WorkflowArgs, WorkflowCancelArgs, WorkflowCommand, WorkflowDetailArgs, WorkflowGetArgs,
    WorkflowInputsArgs, WorkflowLogsArgs, WorkflowOutputArgs, WorkflowRerunArgs, WorkflowRmArgs, WorkflowRunArgs,
    WorkflowRunsArgs,
};
use crate::client::build_client_with_auth;
use crate::output::format::{pad_display, principal_display, truncate_with_marker};

const WORKFLOW_TRIGGER_APP: &str = "workflow";

pub async fn workflow(cli: &Cli, args: &WorkflowArgs) -> Result<i32> {
    match &args.command {
        WorkflowCommand::Add(a) => add(cli, a).await,
        WorkflowCommand::Get(a) => get(cli, a).await,
        WorkflowCommand::List(_) => list(cli).await,
        WorkflowCommand::Rm(a) => rm(cli, a).await,
        WorkflowCommand::Run(a) => run(cli, a).await,
        WorkflowCommand::Runs(a) => runs(cli, a).await,
        WorkflowCommand::Logs(a) => logs(cli, a).await,
        WorkflowCommand::Output(a) => output(cli, a).await,
        WorkflowCommand::Cancel(a) => cancel(cli, a).await,
        WorkflowCommand::Rerun(a) => rerun(cli, a).await,
        WorkflowCommand::Detail(a) => detail(cli, a).await,
        WorkflowCommand::Inputs(a) => inputs(cli, a).await,
    }
}

fn task_err(action: &str) -> String {
    format!("Failed to {}. Is workflow engine running?", action)
}

/// A run_task failure on the workflow engine App with a usable cause: don't blame the
/// engine when the caller's token was the problem (a rejected bearer shows up as a
/// typed 401/403 — at connect for the WebSocket handshake, or on the task request —
/// while the engine itself is fine and running).
fn task_hint(action: &str, err: appmesh::AppMeshError) -> anyhow::Error {
	let hint = match &err {
		appmesh::AppMeshError::RequestFailed { status, .. } if status.as_u16() == 401 =>
			"the access token was rejected (expired or invalid) — re-run 'appm logon' or refresh APPMESH_BEARER_TOKEN",
		appmesh::AppMeshError::RequestFailed { status, .. } if status.as_u16() == 403 =>
			"the access token lacks the required permission for this workflow action",
		appmesh::AppMeshError::AuthenticationFailed(_) =>
			"authentication failed — re-run 'appm logon' or refresh APPMESH_BEARER_TOKEN",
		appmesh::AppMeshError::PermissionDenied(_) =>
			"the access token lacks the required permission for this workflow action",
		_ => return anyhow::Error::from(err).context(task_err(action)),
	};
	anyhow::Error::from(err).context(format!("Failed to {}: {}", action, hint))
}

fn parse_resp(resp: &str) -> Result<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(resp)?;
    if v.get("status").and_then(|s| s.as_str()) == Some("error") {
        bail!("{}", v.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error"));
    }
    Ok(v)
}

/// Attach the caller's access token to a workflow action payload. The engine
/// authenticates the action from this token, keeps it in memory for optional
/// shared-issuer forwarding, and uses an Engine-issued capability for local steps.
/// The engine is fail-closed, so a payload without a token is rejected.
fn with_token(client: &appmesh::AppMeshClientWSS, mut payload: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("token".to_string(), json!(client.get_access_token()));
    }
    payload
}

async fn add(cli: &Cli, args: &WorkflowAddArgs) -> Result<i32> {
    // Validate the local file before any network call.
    let path = std::path::Path::new(&args.file);
    if !path.exists() {
        bail!("File not found: {}", args.file);
    }
    let content = std::fs::read_to_string(path)?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)?;
    let name = yaml.get("name").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("YAML must have 'name'"))?;

    let client = build_client_with_auth(cli).await?;
    let payload = with_token(&client, json!({"action" : "workflow_add", "workflow" : name, "content" : content}));
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, payload, 30).await.map_err(|e| task_hint("add", e))?;
    let v = parse_resp(&resp)?;
    eprintln!("{}", v["message"].as_str().unwrap_or("ok"));
    Ok(0)
}

async fn get(cli: &Cli, args: &WorkflowGetArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(WORKFLOW_TRIGGER_APP, with_token(&client, json!({"action" : "workflow_get", "workflow" : args.name})), 10)
        .await
        .map_err(|e| task_hint("get", e))?;
    let v = parse_resp(&resp)?;
    if let Some(d) = v["data"].as_str() {
        println!("{}", d);
    }
    Ok(0)
}

async fn list(cli: &Cli) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(WORKFLOW_TRIGGER_APP, with_token(&client, json!({"action" : "workflow_list"})), 10)
        .await
        .map_err(|e| task_hint("list", e))?;
    let v = parse_resp(&resp)?;
    let wfs = v["data"].as_array().cloned().unwrap_or_default();
    if wfs.is_empty() {
        eprintln!("No workflows registered.");
        return Ok(0);
    }
    // OWNER prefers a response-only display label and falls back to the stable
    // Principal ID when the issuer supplied no human-readable name.
    println!(
        "{} {} {} {}",
        pad_display("WORKFLOW", 25),
        pad_display("OWNER", 18),
        pad_display("LAST STATUS", 12),
        pad_display("LAST RUN", 25)
    );
    println!("{}", "-".repeat(83));
    for w in &wfs {
        let owner = principal_display(w["owner"].as_str().unwrap_or("-"), w["owner_display_name"].as_str());
        println!(
            "{} {} {} {}",
            pad_display(w["name"].as_str().unwrap_or("-"), 25),
            pad_display(&truncate_with_marker(&owner, 18), 18),
            pad_display(w["last_run_status"].as_str().unwrap_or("-"), 12),
            pad_display(w["last_run_at"].as_str().unwrap_or("-"), 25)
        );
    }
    Ok(0)
}

async fn rm(cli: &Cli, args: &WorkflowRmArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(WORKFLOW_TRIGGER_APP, with_token(&client, json!({"action" : "workflow_rm", "workflow" : args.name})), 10)
        .await
        .map_err(|e| task_hint("rm", e))?;
    let v = parse_resp(&resp)?;
    eprintln!("{}", v["message"].as_str().unwrap_or("ok"));
    Ok(0)
}

async fn run(cli: &Cli, args: &WorkflowRunArgs) -> Result<i32> {
    // Validate inputs locally before any network call.
    let mut inputs = serde_json::Map::new();
    for input in &args.input {
        let Some((k, v)) = input.split_once('=') else {
            bail!("Invalid input '{}': expected key=value", input);
        };
        // Same identifier rule as the engine's parser: [A-Za-z_][A-Za-z0-9_]*
        let mut chars = k.chars();
        let valid = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            bail!("Input key '{}' must match [A-Za-z_][A-Za-z0-9_]*", k);
        }
        inputs.insert(k.to_string(), json!(v));
    }
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(
            WORKFLOW_TRIGGER_APP,
            with_token(&client, json!({"action" : "run", "workflow" : args.name, "inputs" : inputs})),
            30,
        )
        .await
        .map_err(|e| task_hint("run", e))?;
    let v = parse_resp(&resp)?;
    let run_id = v["data"]["run_id"].as_str().unwrap_or("").to_string();
    let status = v["message"].as_str().unwrap_or("ok");
    if !run_id.is_empty() {
        eprintln!("{} (run_id: {})", status, run_id);
    } else {
        eprintln!("{}", status);
    }

    if args.follow && !run_id.is_empty() {
        follow_run(&client, &args.name, &run_id).await?;
    }
    Ok(0)
}

async fn follow_run(client: &Arc<appmesh::AppMeshClientWSS>, workflow: &str, run_id: &str) -> Result<()> {
    let mut log_offset = 0usize;
    let mut errors = 0u32;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let mut iter_ok = false;

        match client
            .run_task(
                WORKFLOW_TRIGGER_APP,
                with_token(client, json!({"action" : "log", "workflow" : workflow, "run_id" : run_id})),
                10,
            )
            .await
        {
            Ok(resp) => {
                iter_ok = true;
                if let Ok(v) = parse_resp(&resp) {
                    if let Some(log) = v["data"].as_str() {
                        // Slice by byte offset only at a valid char boundary; a
                        // multibyte char straddling log_offset would otherwise panic.
                        if let Some(delta) = log.get(log_offset..) {
                            if !delta.is_empty() {
                                print!("{}", delta);
                                log_offset = log.len();
                            }
                        } else if log.len() < log_offset {
                            // Log shrank/rotated unexpectedly — resync from the start.
                            print!("{}", log);
                            log_offset = log.len();
                        }
                    }
                }
            }
            Err(_) => {}
        }

        match client
            .run_task(
                WORKFLOW_TRIGGER_APP,
                with_token(client, json!({"action" : "run_detail", "workflow" : workflow, "run_id" : run_id})),
                10,
            )
            .await
        {
            Ok(resp) => {
                iter_ok = true;
                if let Ok(v) = parse_resp(&resp) {
                    let status = v["data"]["status"].as_str().unwrap_or("");
                    if status == "success" || status == "failure" || status == "cancelled" {
                        break;
                    }
                }
            }
            Err(_) => {}
        }

        if iter_ok {
            errors = 0;
        } else {
            errors += 1;
            if errors >= 5 {
                bail!("Lost connection while following run");
            }
        }
    }
    Ok(())
}

async fn runs(cli: &Cli, args: &WorkflowRunsArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(WORKFLOW_TRIGGER_APP, with_token(&client, json!({"action" : "runs", "workflow" : args.name})), 10)
        .await
        .map_err(|e| task_hint("runs", e))?;
    let v = parse_resp(&resp)?;
    let entries = v["data"].as_array().cloned().unwrap_or_default();
    if entries.is_empty() {
        eprintln!("No runs.");
        return Ok(0);
    }
    println!(
        "{} {} {} {}",
        pad_display("RUN ID", 15),
        pad_display("STATUS", 10),
        pad_display("STARTED", 25),
        pad_display("DURATION", 10)
    );
    println!("{}", "-".repeat(65));
    for e in entries.iter().rev() {
        let dur = e["duration"].as_f64().unwrap_or(0.0);
        let dur_text = if dur > 0.0 { format!("{:.1}s", dur) } else { "-".into() };
        println!(
            "{} {} {} {}",
            pad_display(e["run_id"].as_str().unwrap_or("-"), 15),
            pad_display(e["status"].as_str().unwrap_or("-"), 10),
            pad_display(e["started_at"].as_str().unwrap_or("-"), 25),
            pad_display(&dur_text, 10)
        );
    }
    Ok(0)
}

async fn logs(cli: &Cli, args: &WorkflowLogsArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(
            WORKFLOW_TRIGGER_APP,
            with_token(&client, json!({"action" : "log", "workflow" : args.workflow, "run_id" : args.run_id})),
            10,
        )
        .await
        .map_err(|e| task_hint("logs", e))?;
    let v = parse_resp(&resp)?;
    if let Some(d) = v["data"].as_str() {
        print!("{}", d);
    }
    Ok(0)
}

async fn output(cli: &Cli, args: &WorkflowOutputArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(
            WORKFLOW_TRIGGER_APP,
            with_token(
                &client,
                json!({
                    "action" : "step_log",
                    "workflow" : args.workflow,
                    "run_id" : args.run_id,
                    "job" : args.job,
                    "step" : args.step
                }),
            ),
            10,
        )
        .await
        .map_err(|e| task_hint("output", e))?;
    let v = parse_resp(&resp)?;
    if let Some(d) = v["data"].as_str() {
        print!("{}", d);
    }
    Ok(0)
}

async fn cancel(cli: &Cli, args: &WorkflowCancelArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(
            WORKFLOW_TRIGGER_APP,
            with_token(&client, json!({"action" : "cancel", "workflow" : args.workflow, "run_id" : args.run_id})),
            10,
        )
        .await
        .map_err(|e| task_hint("cancel", e))?;
    let v = parse_resp(&resp)?;
    eprintln!("{}", v["message"].as_str().unwrap_or("ok"));
    Ok(0)
}

async fn rerun(cli: &Cli, args: &WorkflowRerunArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(
            WORKFLOW_TRIGGER_APP,
            with_token(&client, json!({"action" : "rerun", "workflow" : args.workflow, "run_id" : args.run_id})),
            30,
        )
        .await
        .map_err(|e| task_hint("rerun", e))?;
    let v = parse_resp(&resp)?;
    let run_id = v["data"]["run_id"].as_str().unwrap_or("");
    let status = v["message"].as_str().unwrap_or("ok");
    if !run_id.is_empty() {
        eprintln!("{} (run_id: {})", status, run_id);
    } else {
        eprintln!("{}", status);
    }
    Ok(0)
}

async fn detail(cli: &Cli, args: &WorkflowDetailArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(
            WORKFLOW_TRIGGER_APP,
            with_token(&client, json!({"action" : "run_detail", "workflow" : args.workflow, "run_id" : args.run_id})),
            10,
        )
        .await
        .map_err(|e| task_hint("detail", e))?;
    let v = parse_resp(&resp)?;
    println!("{}", serde_json::to_string_pretty(&v["data"])?);
    Ok(0)
}

async fn inputs(cli: &Cli, args: &WorkflowInputsArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client
        .run_task(
            WORKFLOW_TRIGGER_APP,
            with_token(&client, json!({"action" : "workflow_inputs", "workflow" : args.name})),
            10,
        )
        .await
        .map_err(|e| task_hint("inputs", e))?;
    let v = parse_resp(&resp)?;
    let data = &v["data"];
    if let Some(obj) = data.as_object() {
        if obj.is_empty() {
            eprintln!("No inputs defined.");
            return Ok(0);
        }
        println!(
            "{} {} {} {} {}",
            pad_display("NAME", 20),
            pad_display("TYPE", 10),
            pad_display("REQUIRED", 10),
            pad_display("DEFAULT", 15),
            "DESCRIPTION"
        );
        println!("{}", "-".repeat(75));
        for (name, def) in obj {
            let required = if def["required"].as_bool().unwrap_or(false) { "true" } else { "false" };
            let default_text = def.get("default").map(|d| d.to_string()).unwrap_or_else(|| "-".into());
            println!(
                "{} {} {} {} {}",
                pad_display(name, 20),
                pad_display(def["type"].as_str().unwrap_or("-"), 10),
                pad_display(required, 10),
                pad_display(&default_text, 15),
                def["description"].as_str().unwrap_or("")
            );
        }
    } else {
        eprintln!("No inputs defined.");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
	use super::task_hint;
	use appmesh::AppMeshError;
	use http::StatusCode;

	fn message(err: AppMeshError) -> String {
		task_hint("run", err).to_string()
	}

	// The hint must follow the typed cause: a rejected token is not "engine down".
	#[test]
	fn token_rejections_get_token_hints() {
		let msg = message(AppMeshError::RequestFailed {
			status:  StatusCode::UNAUTHORIZED,
			message: "WebSocket connect failed: 401".into(),
		});
		assert!(msg.contains("access token was rejected"), "{msg}");
		assert!(!msg.contains("Is workflow engine running"), "{msg}");

		let msg = message(AppMeshError::RequestFailed {
			status:  StatusCode::FORBIDDEN,
			message: String::new(),
		});
		assert!(msg.contains("lacks the required permission"), "{msg}");

		assert!(message(AppMeshError::AuthenticationFailed("oauth".into())).contains("appm logon"));
	}

	#[test]
	fn transport_failures_keep_the_engine_hint() {
		let msg = message(AppMeshError::ConnectionError("refused".into()));
		assert!(msg.contains("Is workflow engine running"), "{msg}");
	}
}

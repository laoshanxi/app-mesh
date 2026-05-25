use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::app::{
    Cli, WorkflowAddArgs, WorkflowArgs, WorkflowCancelArgs, WorkflowCommand, WorkflowDetailArgs,
    WorkflowGetArgs, WorkflowInputsArgs, WorkflowLogsArgs, WorkflowOutputArgs, WorkflowRerunArgs,
    WorkflowRmArgs, WorkflowRunArgs, WorkflowRunsArgs,
};
use crate::client::build_client_with_auth;

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

fn parse_resp(resp: &str) -> Result<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(resp)?;
    if v.get("status").and_then(|s| s.as_str()) == Some("error") {
        bail!("{}", v.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error"));
    }
    Ok(v)
}

async fn add(cli: &Cli, args: &WorkflowAddArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let path = std::path::Path::new(&args.file);
    if !path.exists() { bail!("File not found: {}", args.file); }
    let content = std::fs::read_to_string(path)?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)?;
    let name = yaml.get("name").and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("YAML must have 'name'"))?;

    let payload = json!({"action": "workflow_add", "workflow": name, "content": content});
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, payload, 30).await.context(task_err("add"))?;
    let v = parse_resp(&resp)?;
    eprintln!("{}", v["message"].as_str().unwrap_or("ok"));
    Ok(0)
}

async fn get(cli: &Cli, args: &WorkflowGetArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "workflow_get", "workflow": args.name}), 10).await.context(task_err("get"))?;
    let v = parse_resp(&resp)?;
    if let Some(d) = v["data"].as_str() { println!("{}", d); }
    Ok(0)
}

async fn list(cli: &Cli) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "workflow_list"}), 10).await.context(task_err("list"))?;
    let v = parse_resp(&resp)?;
    let wfs = v["data"].as_array().cloned().unwrap_or_default();
    if wfs.is_empty() { eprintln!("No workflows registered."); return Ok(0); }
    println!("{:<25} {:<12} {:<12} {:<25}", "WORKFLOW", "OWNER", "LAST STATUS", "LAST RUN");
    println!("{}", "-".repeat(75));
    for w in &wfs {
        println!("{:<25} {:<12} {:<12} {:<25}",
            w["name"].as_str().unwrap_or("-"),
            w["owner"].as_str().unwrap_or("-"),
            w["last_run_status"].as_str().unwrap_or("-"),
            w["last_run_at"].as_str().unwrap_or("-"));
    }
    Ok(0)
}

async fn rm(cli: &Cli, args: &WorkflowRmArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "workflow_rm", "workflow": args.name}), 10).await.context(task_err("rm"))?;
    let v = parse_resp(&resp)?;
    eprintln!("{}", v["message"].as_str().unwrap_or("ok"));
    Ok(0)
}

async fn run(cli: &Cli, args: &WorkflowRunArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let mut inputs = serde_json::Map::new();
    for input in &args.input {
        if let Some((k, v)) = input.split_once('=') {
            if !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                bail!("Input key '{}' must be [A-Za-z0-9_]", k);
            }
            inputs.insert(k.to_string(), json!(v));
        }
    }
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "run", "workflow": args.name, "inputs": inputs}), 30).await.context(task_err("run"))?;
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

        match client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "log", "workflow": workflow, "run_id": run_id}), 10).await {
            Ok(resp) => {
                iter_ok = true;
                if let Ok(v) = parse_resp(&resp) {
                    if let Some(log) = v["data"].as_str() {
                        if log.len() > log_offset {
                            print!("{}", &log[log_offset..]);
                            log_offset = log.len();
                        }
                    }
                }
            }
            Err(_) => {}
        }

        match client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "run_detail", "workflow": workflow, "run_id": run_id}), 10).await {
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
            if errors >= 5 { bail!("Lost connection while following run"); }
        }
    }
    Ok(())
}

async fn runs(cli: &Cli, args: &WorkflowRunsArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "runs", "workflow": args.name}), 10).await.context(task_err("runs"))?;
    let v = parse_resp(&resp)?;
    let entries = v["data"].as_array().cloned().unwrap_or_default();
    if entries.is_empty() { eprintln!("No runs."); return Ok(0); }
    println!("{:<15} {:<10} {:<25} {:<10}", "RUN ID", "STATUS", "STARTED", "DURATION");
    println!("{}", "-".repeat(65));
    for e in entries.iter().rev() {
        let dur = e["duration"].as_f64().unwrap_or(0.0);
        println!("{:<15} {:<10} {:<25} {:<10}",
            e["run_id"].as_str().unwrap_or("-"),
            e["status"].as_str().unwrap_or("-"),
            e["started_at"].as_str().unwrap_or("-"),
            if dur > 0.0 { format!("{:.1}s", dur) } else { "-".into() });
    }
    Ok(0)
}

async fn logs(cli: &Cli, args: &WorkflowLogsArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "log", "workflow": args.workflow, "run_id": args.run_id}), 10).await.context(task_err("logs"))?;
    let v = parse_resp(&resp)?;
    if let Some(d) = v["data"].as_str() { print!("{}", d); }
    Ok(0)
}

async fn output(cli: &Cli, args: &WorkflowOutputArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "step_log", "workflow": args.workflow, "run_id": args.run_id, "job": args.job, "step": args.step}), 10).await.context(task_err("output"))?;
    let v = parse_resp(&resp)?;
    if let Some(d) = v["data"].as_str() { print!("{}", d); }
    Ok(0)
}

async fn cancel(cli: &Cli, args: &WorkflowCancelArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "cancel", "workflow": args.workflow, "run_id": args.run_id}), 10).await.context(task_err("cancel"))?;
    let v = parse_resp(&resp)?;
    eprintln!("{}", v["message"].as_str().unwrap_or("ok"));
    Ok(0)
}

async fn rerun(cli: &Cli, args: &WorkflowRerunArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "rerun", "workflow": args.workflow, "run_id": args.run_id}), 30).await.context(task_err("rerun"))?;
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
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "run_detail", "workflow": args.workflow, "run_id": args.run_id}), 10).await.context(task_err("detail"))?;
    let v = parse_resp(&resp)?;
    println!("{}", serde_json::to_string_pretty(&v["data"])?);
    Ok(0)
}

async fn inputs(cli: &Cli, args: &WorkflowInputsArgs) -> Result<i32> {
    let client = build_client_with_auth(cli).await?;
    let resp = client.run_task(WORKFLOW_TRIGGER_APP, json!({"action": "workflow_inputs", "workflow": args.name}), 10).await.context(task_err("inputs"))?;
    let v = parse_resp(&resp)?;
    let data = &v["data"];
    if let Some(obj) = data.as_object() {
        if obj.is_empty() { eprintln!("No inputs defined."); return Ok(0); }
        println!("{:<20} {:<10} {:<10} {:<15} {}", "NAME", "TYPE", "REQUIRED", "DEFAULT", "DESCRIPTION");
        println!("{}", "-".repeat(75));
        for (name, def) in obj {
            println!("{:<20} {:<10} {:<10} {:<15} {}",
                name,
                def["type"].as_str().unwrap_or("-"),
                def["required"].as_bool().unwrap_or(false),
                def.get("default").map(|d| d.to_string()).unwrap_or_else(|| "-".into()),
                def["description"].as_str().unwrap_or(""));
        }
    } else {
        eprintln!("No inputs defined.");
    }
    Ok(0)
}

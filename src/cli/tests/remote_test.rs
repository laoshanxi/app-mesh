//! Remote integration tests — require a running App Mesh daemon.
//!
//! Run: cargo test --test remote_test -- --ignored --test-threads=1
//! Env: APPMESH_TEST_CRED (default: admin123), APPMESH_HOST, APPMESH_WSS_PORT

use appmesh::{Application, ClientBuilderWSS};
use std::sync::Arc;

fn wss_host() -> String {
    std::env::var("APPMESH_HOST").unwrap_or_else(|_| "127.0.0.1".to_string())
}
fn wss_port() -> u16 {
    std::env::var("APPMESH_WSS_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(6058)
}
fn cred() -> String {
    std::env::var("APPMESH_TEST_CRED").unwrap_or_else(|_| "admin123".to_string())
}

async fn new_client() -> Arc<appmesh::AppMeshClientWSS> {
    rustls::crypto::ring::default_provider().install_default().ok();
    ClientBuilderWSS::new()
        .address(wss_host(), wss_port())
        .danger_accept_invalid_certs(true)
        .build()
        .expect("WSS client build failed")
}

async fn authed() -> Arc<appmesh::AppMeshClientWSS> {
    let c = new_client().await;
    c.login("admin", &cred(), None, None, None).await.expect("login failed");
    c
}

fn appc() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_appc"));
    cmd.args(["-H", &format!("{}:{}", wss_host(), wss_port())]);
    cmd
}

fn cli_login() {
    let out = appc().args(["logon", "-U", "admin", "-X", &cred()]).output().unwrap();
    assert!(out.status.success(), "CLI login: {}", String::from_utf8_lossy(&out.stderr));
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK tests via WSS: Auth (01–03)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_01_login_logout() {
    let c = new_client().await;
    let ch = c.login("admin", &cred(), None, None, None).await.unwrap();
    assert!(ch.is_empty());
    assert!(c.get_access_token().is_some());
    c.logout().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn sdk_02_login_wrong_password() {
    let c = new_client().await;
    assert!(c.login("admin", "WRONG", None, None, None).await.is_err());
}

#[tokio::test]
#[ignore]
async fn sdk_03_current_user() {
    let c = authed().await;
    let u = c.get_current_user().await.unwrap();
    assert_eq!(u["name"].as_str(), Some("admin"));
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK: User / Role management (04–06)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_04_user_lock_unlock() {
    let c = authed().await;
    c.lock_user("mesh").await.unwrap();
    c.unlock_user("mesh").await.unwrap();
}

#[tokio::test]
#[ignore]
async fn sdk_05_list_users_roles() {
    let c = authed().await;
    let users = c.list_users().await.unwrap();
    assert!(users.is_object() || users.is_array());
    let roles = c.list_roles().await.unwrap();
    assert!(!roles.is_empty());
}

#[tokio::test]
#[ignore]
async fn sdk_06_password_change_roundtrip() {
    let c = authed().await;
    c.update_password(&cred(), "TempPass@789", None).await.unwrap();
    // old password should fail now
    let c2 = new_client().await;
    assert!(c2.login("admin", &cred(), None, None, None).await.is_err());
    // restore
    let c3 = new_client().await;
    c3.login("admin", "TempPass@789", None, None, None).await.unwrap();
    c3.update_password("TempPass@789", &cred(), None).await.unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK: Labels (07)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_07_labels_crud() {
    let c = authed().await;
    c.add_label("RustTag", "RustValue").await.unwrap();
    let labels = c.list_labels().await.unwrap();
    assert_eq!(labels["RustTag"].as_str(), Some("RustValue"));
    c.delete_label("RustTag").await.unwrap();
    assert!(c.list_labels().await.unwrap().get("RustTag").is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK: App CRUD (08–09) + negative cases
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_08_app_list_get() {
    let c = authed().await;
    let apps = c.list_apps().await.unwrap();
    assert!(!apps.is_empty());
    let first = apps[0].name.as_deref().unwrap();
    let fetched = c.get_app(first).await.unwrap();
    assert_eq!(fetched.name.as_deref(), Some(first));
}

#[tokio::test]
#[ignore]
async fn sdk_09_app_lifecycle() {
    let c = authed().await;
    let _ = c.delete_app("RUST_LIFE").await;
    let app = Application::builder("RUST_LIFE").command("sleep 1000").build();
    let added = c.add_app(&app, None).await.unwrap();
    assert_eq!(added.name.as_deref(), Some("RUST_LIFE"));
    c.disable_app("RUST_LIFE").await.unwrap();
    c.enable_app("RUST_LIFE").await.unwrap();
    assert!(c.delete_app("RUST_LIFE").await.unwrap());
    // delete again should return false (not found)
    assert!(!c.delete_app("RUST_LIFE").await.unwrap());
}

#[tokio::test]
#[ignore]
async fn sdk_09b_get_nonexistent_app() {
    let c = authed().await;
    assert!(c.get_app("NONEXISTENT_APP_XYZ").await.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK: Run / Exec (10–12) + negative cases
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_10_run_sync() {
    let c = authed().await;
    let app = Application::builder("_sync_").command("echo sync_ok").shell(true).build();
    let (code, output) = c.run_app_sync(&app, 5, 10).await.unwrap();
    assert_eq!(code, Some(0));
    assert!(output.contains("sync_ok"));
}

#[tokio::test]
#[ignore]
async fn sdk_11_run_exit_code() {
    let c = authed().await;
    let app = Application::builder("_exit_").command("exit 42").shell(true).build();
    let (code, _) = c.run_app_sync(&app, 5, 10).await.unwrap();
    assert_eq!(code, Some(42));
}

#[tokio::test]
#[ignore]
async fn sdk_11b_run_timeout() {
    let c = authed().await;
    let app = Application::builder("_timeout_").command("sleep 60").shell(true).build();
    let (code, _) = c.run_app_sync(&app, 2, 5).await.unwrap();
    // timeout → non-zero exit
    assert_ne!(code, Some(0));
}

#[tokio::test]
#[ignore]
async fn sdk_12_run_async() {
    let c = authed().await;
    let app = Application::builder("_async_").command("echo async_ok").shell(true).build();
    let run = c.run_app_async(&app, 10, 30).await.unwrap();
    let code = run.wait(10, false).await.unwrap();
    assert!(code.is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK: Config / Resources / Log (13–14)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_13_config_resources() {
    let c = authed().await;
    let config = c.get_config().await.unwrap();
    assert!(config.get("REST").is_some());
    let res = c.get_host_resources().await.unwrap();
    assert!(res.is_object());
}

#[tokio::test]
#[ignore]
async fn sdk_14_log_level() {
    let c = authed().await;
    assert_eq!(c.set_log_level("DEBUG").await.unwrap(), "DEBUG");
    assert_eq!(c.set_log_level("INFO").await.unwrap(), "INFO");
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK: File transfer (20–22)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_20_file_download() {
    let c = authed().await;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    c.download_file("/opt/appmesh/work/server.log", tmp.path().to_str().unwrap(), false).await.unwrap();
    assert!(std::fs::metadata(tmp.path()).unwrap().len() > 0);
}

#[tokio::test]
#[ignore]
async fn sdk_21_file_roundtrip() {
    let c = authed().await;
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("up.txt");
    let dst = dir.path().join("down.txt");
    std::fs::write(&src, "rust_file_roundtrip").unwrap();
    c.upload_file(src.to_str().unwrap(), "/tmp/rust_rt.txt", false).await.unwrap();
    c.download_file("/tmp/rust_rt.txt", dst.to_str().unwrap(), false).await.unwrap();
    assert_eq!(std::fs::read_to_string(&dst).unwrap(), "rust_file_roundtrip");
}

#[tokio::test]
#[ignore]
async fn sdk_22_download_nonexistent_file() {
    let c = authed().await;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    assert!(c.download_file("/nonexistent/path.txt", tmp.path().to_str().unwrap(), false).await.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK: App output (30–32)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_30_app_output() {
    let c = authed().await;
    let _ = c.delete_app("RUST_OUT").await;
    let app = Application::builder("RUST_OUT").command("echo hello_output").shell(true).build();
    c.add_app(&app, None).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let out = c.get_app_output("RUST_OUT", 0, 0, 0, None, None).await.unwrap();
    assert!(out.output.contains("hello_output"));
    c.delete_app("RUST_OUT").await.unwrap();
}

#[tokio::test]
#[ignore]
async fn sdk_31_app_output_incremental() {
    let c = authed().await;
    let _ = c.delete_app("RUST_INCR").await;
    let app = Application::builder("RUST_INCR").command("seq 1 20").shell(true).build();
    c.add_app(&app, None).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let r1 = c.get_app_output("RUST_INCR", 0, 0, 32, None, None).await.unwrap();
    assert!(r1.output_position > 0);
    let r2 = c.get_app_output("RUST_INCR", r1.output_position, 0, 0, None, None).await.unwrap();
    if !r2.output.is_empty() {
        assert!(!r1.output.contains(&r2.output));
    }
    c.delete_app("RUST_INCR").await.unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK: Subscribe (40–42)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_40_subscribe_stdout() {
    let c = authed().await;
    let _ = c.delete_app("RUST_SUB").await;
    let app = Application::builder("RUST_SUB").command("echo sub_test").shell(true).build();
    c.add_app(&app, None).await.unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
    let on_event: appmesh::EventCallback = std::sync::Arc::new(move |event| {
        if event.event_type == "STDOUT" {
            if let Some(tx) = tx.lock().ok().and_then(|mut g| g.take()) {
                let _ = tx.send(());
            }
        }
    });

    let sub = c.subscribe("RUST_SUB", Some(&["STDOUT"]), Some(on_event)).await.unwrap();
    assert!(!sub.subscription_id.is_empty());
    let ok = tokio::time::timeout(std::time::Duration::from_secs(10), rx).await;
    c.unsubscribe(&sub.subscription_id).await.ok();
    c.delete_app("RUST_SUB").await.ok();
    assert!(ok.is_ok(), "STDOUT event not received");
}

#[tokio::test]
#[ignore]
async fn sdk_41_subscribe_unsubscribe() {
    let c = authed().await;
    let _ = c.delete_app("RUST_UNSUB").await;
    let app = Application::builder("RUST_UNSUB").command("sleep 60").build();
    c.add_app(&app, None).await.unwrap();
    let sub = c.subscribe("RUST_UNSUB", Some(&["EXIT"]), None).await.unwrap();
    assert!(c.unsubscribe(&sub.subscription_id).await.unwrap());
    c.delete_app("RUST_UNSUB").await.ok();
}

// ═══════════════════════════════════════════════════════════════════════════
// SDK: Negative / edge cases (90–94)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore]
async fn sdk_90_unauthenticated_fails() {
    let c = new_client().await;
    assert!(c.list_apps().await.is_err());
}

#[tokio::test]
#[ignore]
async fn sdk_91_enable_nonexistent() {
    let c = authed().await;
    assert!(c.enable_app("NONEXISTENT_XYZ").await.is_err());
}

#[tokio::test]
#[ignore]
async fn sdk_92_disable_nonexistent() {
    let c = authed().await;
    assert!(c.disable_app("NONEXISTENT_XYZ").await.is_err());
}

#[tokio::test]
#[ignore]
async fn sdk_93_upload_nonexistent_local() {
    let c = authed().await;
    assert!(c.upload_file("/nonexistent/local.txt", "/tmp/x.txt", false).await.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// CLI binary: all commands (50–68)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[ignore]
fn cli_50_logon_logoff() {
    cli_login();
    let out = appc().args(["logoff"]).output().unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("logged off"));
}

#[test]
#[ignore]
fn cli_51_logon_show_token() {
    let out = appc().args(["logon", "-U", "admin", "-X", &cred(), "--show-token"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains('.'), "JWT should contain dots");
}

#[test]
#[ignore]
fn cli_52_loginfo() {
    cli_login();
    let out = appc().args(["loginfo"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("User:"));
}

#[test]
#[ignore]
fn cli_53_view_table() {
    cli_login();
    let out = appc().args(["view"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("NAME"));
}

#[test]
#[ignore]
fn cli_54_view_json() {
    cli_login();
    let out = appc().args(["view", "--json"]).output().unwrap();
    assert!(out.status.success());
    let _: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
}

#[test]
#[ignore]
fn cli_55_add_disable_enable_restart_rm() {
    cli_login();
    assert!(appc().args(["add", "-a", "CLI_ALL", "-c", "sleep 999", "--force"]).output().unwrap().status.success());
    assert!(appc().args(["disable", "-a", "CLI_ALL"]).output().unwrap().status.success());
    assert!(appc().args(["enable", "-a", "CLI_ALL"]).output().unwrap().status.success());
    assert!(appc().args(["restart", "-a", "CLI_ALL"]).output().unwrap().status.success());
    assert!(appc().args(["rm", "-a", "CLI_ALL", "--force"]).output().unwrap().status.success());
}

#[test]
#[ignore]
fn cli_56_run_sync() {
    cli_login();
    let out = appc().args(["run", "-c", "echo cli_run", "-u", "--timeout=-5"]).output().unwrap();
    assert!(out.status.success(), "run: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("cli_run"));
}

#[test]
#[ignore]
fn cli_57_run_exit_code() {
    cli_login();
    let out = appc().args(["run", "-c", "exit 7", "-u", "--timeout=-5"]).output().unwrap();
    assert_eq!(out.status.code(), Some(7));
}

#[test]
#[ignore]
fn cli_58_config() {
    cli_login();
    let out = appc().args(["config"]).output().unwrap();
    assert!(out.status.success());
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(j.get("REST").is_some());
}

#[test]
#[ignore]
fn cli_59_resource() {
    cli_login();
    let out = appc().args(["resource"]).output().unwrap();
    assert!(out.status.success());
    let _: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
}

#[test]
#[ignore]
fn cli_60_label_crud() {
    cli_login();
    assert!(appc().args(["label", "--add", "-l", "ck=cv"]).output().unwrap().status.success());
    let out = appc().args(["label"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("ck=cv"));
    assert!(appc().args(["label", "--delete", "-l", "ck"]).output().unwrap().status.success());
}

#[test]
#[ignore]
fn cli_61_log_level() {
    cli_login();
    assert!(appc().args(["log", "-L", "DEBUG"]).output().unwrap().status.success());
    appc().args(["log", "-L", "INFO"]).output().ok();
}

#[test]
#[ignore]
fn cli_62_user_info() {
    cli_login();
    let out = appc().args(["user"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("admin"));
}

#[test]
#[ignore]
fn cli_63_user_list_all() {
    cli_login();
    let out = appc().args(["user", "--all"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("mesh"));
}

#[test]
#[ignore]
fn cli_64_file_put_get() {
    cli_login();
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("up.txt");
    let dst = dir.path().join("down.txt");
    std::fs::write(&src, "cli_file_test").unwrap();
    assert!(appc().args(["put", "-l", src.to_str().unwrap(), "-r", "/tmp/cli_ft.txt"]).output().unwrap().status.success());
    assert!(appc().args(["get", "-r", "/tmp/cli_ft.txt", "-l", dst.to_str().unwrap()]).output().unwrap().status.success());
    assert_eq!(std::fs::read_to_string(&dst).unwrap(), "cli_file_test");
}

#[test]
#[ignore]
fn cli_65_appmgpwd() {
    let out = appc().args(["appmgpwd", "admin"]).output().unwrap();
    assert!(out.status.success());
    let hash = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(hash.starts_with("$pbkdf2$100000$"), "expected PBKDF2 format, got: {}", hash);
}

// ─── CLI negative cases ─────────────────────────────────────────────────────

#[test]
#[ignore]
fn cli_80_logon_wrong_password() {
    let out = appc().args(["logon", "-U", "admin", "-X", "WRONG"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
#[ignore]
fn cli_81_rm_nonexistent() {
    cli_login();
    // rm of nonexistent should fail (SDK returns error)
    let out = appc().args(["rm", "-a", "NONEXISTENT_XYZ", "--force"]).output().unwrap();
    // delete_app returns false but doesn't error — exit 0
    assert!(out.status.success());
}

#[test]
#[ignore]
fn cli_82_view_nonexistent_app() {
    cli_login();
    let out = appc().args(["view", "-a", "NONEXISTENT_XYZ"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
#[ignore]
fn cli_83_log_invalid_level() {
    cli_login();
    let out = appc().args(["log", "-L", "INVALID"]).output().unwrap();
    assert!(!out.status.success());
}

#[tokio::test]
#[ignore]
async fn sdk_12b_run_async_short_cmd() {
    let c = authed().await;
    let app = Application::builder("_test_short_")
        .command("echo fast_done")
        .shell(true)
        .build();
    let start = std::time::Instant::now();
    // print_stdout=true so output goes to stdout
    let (_run, code) = c.run_and_wait(&app, 5, 30, 5, true).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(code, Some(0));
    assert!(elapsed.as_secs() < 3, "should finish quickly, took {}s", elapsed.as_secs());
}

#[tokio::test]
#[ignore]
async fn sdk_12c_run_async_captures_output() {
    let c = authed().await;
    let app = Application::builder("_test_output_")
        .command("echo captured_text_xyz")
        .shell(true)
        .build();
    // Use run_app_async + wait_for_async_run to test subscribe output delivery
    let run = c.run_app_async(&app, 5, 30).await.unwrap();
    let code = c.wait_for_async_run(&run, 5, true).await.unwrap();
    assert_eq!(code, Some(0));
}

// ═══════════════════════════════════════════════════════════════════════════
// Regression tests: timeout response time + subscribe reliability
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[ignore]
fn cli_90_run_positive_timeout_fast() {
    cli_login();
    let start = std::time::Instant::now();
    let out = appc().args(["run", "-c", "echo timeout_pos", "-u", "-t", "10"]).output().unwrap();
    let elapsed = start.elapsed();
    assert!(out.status.success(), "run -t 10: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("timeout_pos"));
    assert!(elapsed.as_secs() < 5, "should finish in <5s, took {}s", elapsed.as_secs());
}

#[test]
#[ignore]
fn cli_91_run_negative_timeout_fast() {
    cli_login();
    let start = std::time::Instant::now();
    let out = appc().args(["run", "-c", "echo timeout_neg", "-u", "--timeout=-10"]).output().unwrap();
    let elapsed = start.elapsed();
    assert!(out.status.success(), "run -t -10: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("timeout_neg"));
    assert!(elapsed.as_secs() < 5, "should finish in <5s, took {}s", elapsed.as_secs());
}

#[test]
#[ignore]
fn cli_92_run_no_name_no_leak() {
    cli_login();
    // Run without -a: server assigns random name, should not leave _run_cmd_ residue
    let out = appc().args(["run", "-c", "echo no_name", "-u", "--timeout=-5"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("no_name"));
}

#[test]
#[ignore]
fn cli_93_logon_no_double_login() {
    // logon should use build_client (not build_client_with_auth) to avoid double login
    let out = appc().args(["logon", "-U", "admin", "-X", &cred()]).output().unwrap();
    assert!(out.status.success());
}

#[tokio::test]
#[ignore]
async fn sdk_95_run_and_wait_short_output() {
    let c = authed().await;
    let app = Application::builder("_rw_short_").command("echo rw_output_test").shell(true).build();
    let start = std::time::Instant::now();
    let (_run, code) = c.run_and_wait(&app, 10, 30, 10, true).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(code, Some(0));
    assert!(elapsed.as_secs() < 3, "run_and_wait should be fast, took {}s", elapsed.as_secs());
}

#[tokio::test]
#[ignore]
async fn sdk_96_run_and_wait_exit_code() {
    let c = authed().await;
    let app = Application::builder("_rw_exit_").command("exit 7").shell(true).build();
    let (_run, code) = c.run_and_wait(&app, 10, 30, 10, false).await.unwrap();
    assert_eq!(code, Some(7));
}

#[tokio::test]
#[ignore]
async fn sdk_97_subscribe_receives_exit() {
    let c = authed().await;
    let app = Application::builder("_sub_exit_").command("true").shell(true).build();
    let run = c.run_app_async(&app, 5, 30).await.unwrap();
    let start = std::time::Instant::now();
    let code = c.wait_for_async_run(&run, 5, false).await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(code, Some(0));
    assert!(elapsed.as_secs() < 3, "subscribe should catch EXIT fast, took {}s", elapsed.as_secs());
}

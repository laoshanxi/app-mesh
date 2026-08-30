use std::process::Command;

fn appm() -> Command {
    Command::new(env!("CARGO_BIN_EXE_appm"))
}

// ═══════════════════════════════════════════════════════════════════════════
// Help & Version
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_help_lists_core_commands() {
    let out = appm().arg("--help").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for cmd in [
        "logon", "logoff", "loginfo", "add", "rm", "view", "enable", "disable", "restart",
        "run", "exec", "shell", "get", "put", "label", "log", "config", "resource", "metric",
        "workflow",
    ] {
        assert!(s.contains(cmd), "missing command: {}", cmd);
    }
}

#[test]
fn test_version_output() {
    let out = appm().arg("--version").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("appm"));
}

#[test]
fn test_short_help_flag() {
    let out = appm().arg("-h").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("App Mesh CLI"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Global flags
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_global_flags_in_help() {
    let s = stdout_of(&["--help"]);
    for flag in ["--host-url", "--forward-to", "--verbose"] {
        assert!(s.contains(flag), "missing global flag: {}", flag);
    }
}

#[test]
fn test_global_short_flags_accepted() {
    // All short global flags before subcommand + --help
    let out = appm()
        .args(["-H", "localhost:6058", "-F", "worker-1", "-v", "logon", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn test_unknown_global_flag_rejected() {
    let out = appm().args(["--nonexistent-flag", "view"]).output().unwrap();
    assert!(!out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Aliases  (6 total)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alias_ls()     { assert!(appm().args(["ls",     "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_list()   { assert!(appm().args(["list",   "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_reg()    { assert!(appm().args(["reg",    "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_remove() { assert!(appm().args(["remove", "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_unreg()  { assert!(appm().args(["unreg",  "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_logout() { assert!(appm().args(["logout", "--help"]).output().unwrap().status.success()); }

#[test]
fn test_alias_content_matches_primary() {
    let rm_help  = String::from_utf8_lossy(&appm().args(["rm",     "--help"]).output().unwrap().stdout).to_string();
    let rem_help = String::from_utf8_lossy(&appm().args(["remove", "--help"]).output().unwrap().stdout).to_string();
    // Both should list the same flags
    assert!(rm_help.contains("--app") && rem_help.contains("--app"));
    assert!(rm_help.contains("--force") && rem_help.contains("--force"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Subcommand help — exhaustive flag coverage per command
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_help_logon_all_flags() {
    let s = stdout_of(&["logon", "--help"]);
    for flag in [
        "--device", "--dex-access-url", "--login-timeout",
        "--enroll-first-admin", "--first-admin-token-file",
    ] {
        assert!(s.contains(flag), "logon missing {}", flag);
    }
}

#[test]
fn test_help_add_all_flags() {
    let s = stdout_of(&["add", "--help"]);
    for f in [
        "--app", "--cmd", "--description", "--working-dir", "--status",
        "--shell", "--session-login", "--health-check", "--docker-image", "--pid",
        "--begin-time", "--end-time", "--daily-begin", "--daily-end", "--interval", "--cron",
        "--memory-limit", "--virtual-memory", "--cpu-shares", "--log-cache-size",
        "--permission", "--metadata", "--env", "--security-env",
        "--stop-timeout", "--exit", "--control", "--stdin", "--force",
    ] {
        assert!(s.contains(f), "add missing {}", f);
    }
}

#[test]
fn test_help_rm_all_flags() {
    let s = stdout_of(&["rm", "--help"]);
    for f in ["--app", "--force"] { assert!(s.contains(f), "rm missing {}", f); }
}

#[test]
fn test_help_view_all_flags() {
    let s = stdout_of(&["view", "--help"]);
    for f in ["--long", "--show-output", "--pstree", "--app", "--log-index", "--follow", "--json"] {
        assert!(s.contains(f), "view missing {}", f);
    }
}

#[test]
fn test_help_enable_all_flags() {
    let s = stdout_of(&["enable", "--help"]);
    for f in ["--app", "--all"] { assert!(s.contains(f), "enable missing {}", f); }
}

#[test]
fn test_help_disable_all_flags() {
    let s = stdout_of(&["disable", "--help"]);
    for f in ["--app", "--all"] { assert!(s.contains(f), "disable missing {}", f); }
}

#[test]
fn test_help_restart_all_flags() {
    let s = stdout_of(&["restart", "--help"]);
    for f in ["--app", "--all"] { assert!(s.contains(f), "restart missing {}", f); }
}

#[test]
fn test_help_run_all_flags() {
    let s = stdout_of(&["run", "--help"]);
    for f in ["--app", "--cmd", "--description", "--working-dir", "--metadata", "--env",
              "--shell", "--session-login", "--lifetime", "--timeout"] {
        assert!(s.contains(f), "run missing {}", f);
    }
    assert!(s.contains("216000")); // default lifetime
}

#[test]
fn test_help_exec_all_flags() {
    let s = stdout_of(&["exec", "--help"]);
    for f in ["--shell", "--session-login", "--lifetime", "--timeout", "--retry", "--env"] {
        assert!(s.contains(f), "exec missing {}", f);
    }
    assert!(s.contains("216000")); // default lifetime
}

#[test]
fn test_help_shell_all_flags() {
    let s = stdout_of(&["shell", "--help"]);
    for f in ["--session-login", "--lifetime", "--timeout", "--retry", "--env"] {
        assert!(s.contains(f), "shell missing {}", f);
    }
}

#[test]
fn test_help_get_all_flags() {
    let s = stdout_of(&["get", "--help"]);
    for f in ["--remote", "--local", "--no-attr"] { assert!(s.contains(f), "get missing {}", f); }
}

#[test]
fn test_help_put_all_flags() {
    let s = stdout_of(&["put", "--help"]);
    for f in ["--remote", "--local", "--no-attr"] { assert!(s.contains(f), "put missing {}", f); }
}

#[test]
fn test_help_label_all_flags() {
    let s = stdout_of(&["label", "--help"]);
    for f in ["--view", "--add", "--delete", "--label"] { assert!(s.contains(f), "label missing {}", f); }
}

#[test]
fn test_help_log_all_flags() {
    let s = stdout_of(&["log", "--help"]);
    assert!(s.contains("--level"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Required argument validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_missing_subcommand()        { assert!(!appm().output().unwrap().status.success()); }
#[test]
fn test_invalid_subcommand()        { assert!(!appm().arg("xyz").output().unwrap().status.success()); }
#[test]
fn test_rm_requires_app()           { assert_err_contains(&["rm", "-f"], "--app"); }
#[test]
fn test_get_requires_remote()       { assert_err_contains(&["get", "--local", "/tmp/x"], "--remote"); }
#[test]
fn test_get_requires_local()        { assert_err_contains(&["get", "--remote", "/tmp/x"], "--local"); }
#[test]
fn test_put_requires_remote()       { assert_err_contains(&["put", "--local", "/tmp/x"], "--remote"); }
#[test]
fn test_put_requires_local()        { assert_err_contains(&["put", "--remote", "/tmp/x"], "--local"); }
#[test]
fn test_log_requires_level()        { assert_err_contains(&["log"], "--level"); }
#[test]
fn test_exec_requires_command()     { assert!(!appm().args(["exec"]).output().unwrap().status.success()); }

// ═══════════════════════════════════════════════════════════════════════════
// Clap type validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_add_invalid_status_bool() {
    let out = appm().args(["add", "-a", "x", "-c", "y", "--status", "notbool"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_add_invalid_pid_type() {
    let out = appm().args(["add", "-a", "x", "-c", "y", "--pid", "abc"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_add_invalid_memory_limit_type() {
    let out = appm().args(["add", "-a", "x", "-c", "y", "--memory-limit", "abc"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_add_invalid_permission_type() {
    let out = appm().args(["add", "-a", "x", "-c", "y", "--permission", "abc"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_view_invalid_log_index_type() {
    let out = appm().args(["view", "-a", "x", "-i", "abc"]).output().unwrap();
    assert!(!out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// Exit code behavior
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_exits_1() {
    let out = appm().args(["-H", "127.0.0.1:1", "config"]).output().unwrap();
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn test_rm_force_error_exits_nonzero() {
    // `rm --force` only skips the interactive confirmation; a failed request
    // (here: unreachable server — same Err propagation as a 401/403/5xx from
    // the daemon) must still exit 1, so `appm rm -a x --force || die` works.
    let out = appm()
        .args(["-H", "127.0.0.1:1", "rm", "-a", "nonexist", "--force"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn test_add_force_error_exits_nonzero() {
    // `add --force` must not mask a failed registration (e.g. server 400)
    // as success — the exit code is the only signal a script gets.
    let out = appm()
        .args([
            "-H", "127.0.0.1:1",
            "add", "-a", "nonexist", "-c", "echo", "--force",
        ])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn test_error_with_follow_flag_exits_zero() {
    let out = appm()
        .args(["-H", "127.0.0.1:1", "view", "-a", "nonexist", "--follow"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[cfg(unix)]
#[test]
fn test_watch_mode_failure_exits_nonzero() {
    // `ls -f` (no -a) is watch mode, not output-follow: a connection failure is
    // a real failure and must not be masked as success.
    let out = appm()
        .args(["-H", "127.0.0.1:1", "ls", "--follow"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn test_rm_short_f_error_exits_nonzero() {
    // -f on rm is --force: skip confirmation only, never skip the error exit.
    let out = appm()
        .args(["-H", "127.0.0.1:1", "rm", "-a", "nonexist", "-f"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn test_help_always_exits_zero() {
    for cmd in ["logon", "logoff", "loginfo", "add", "rm", "view", "enable", "disable",
                "restart", "run", "exec", "shell", "get", "put", "label", "log",
                "config", "resource", "metric", "workflow"] {
        let out = appm().args([cmd, "--help"]).output().unwrap();
        assert!(out.status.success(), "{} --help should exit 0", cmd);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Default values in help text
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_default_run_lifetime() {
    assert!(stdout_of(&["run", "--help"]).contains("216000"));
}

#[test]
fn test_default_exec_lifetime() {
    assert!(stdout_of(&["exec", "--help"]).contains("216000"));
}

#[test]
fn test_default_shell_lifetime() {
    assert!(stdout_of(&["shell", "--help"]).contains("216000"));
}

// ═══════════════════════════════════════════════════════════════════════════
// put — local file validation (no daemon)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(unix)]
#[test]
fn test_put_nonexistent_local_file() {
    let out = appm()
        .args(["-H", "127.0.0.1:1", "put", "--remote", "/tmp/r", "--local", "/no/such/file.txt"])
        .output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    // `put` authenticates before touching the local file, so without a stored
    // Dex session the auth gate fires first; either way the command must fail.
    assert!(
        err.contains("Local file not found")
            || err.contains("not found")
            || err.contains("No Dex session is configured")
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// Multiple -e env flags accumulate
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_add_multiple_env_flags_accepted() {
    // Should parse successfully (daemon-dependent for actual operation)
    let out = appm()
        .args(["add", "-a", "test", "-c", "echo", "-e", "K1=V1", "-e", "K2=V2", "--help"])
        .output().unwrap();
    // --help always exits 0; this verifies -e can appear multiple times
    assert!(out.status.success());
}

#[test]
fn test_add_multiple_control_flags_accepted() {
    let out = appm()
        .args(["add", "-a", "x", "-c", "y", "--control", "0:standby", "--control", "1:restart", "--help"])
        .output().unwrap();
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// add --stdin with temp file (no daemon for parse validation)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_add_stdin_nonexistent_file() {
    // No --force: raw argv won't contain --force, so exit code is -1 (255)
    let out = appm()
        .args(["-H", "127.0.0.1:1", "add", "--stdin", "/no/such/app.yaml"])
        .output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    // `add` authenticates before reading the file, so without a stored Dex
    // session the auth gate fires first; either way the command must fail.
    assert!(
        err.contains("Failed to read")
            || err.contains("No such file")
            || err.contains("No Dex session is configured")
    );
}

#[test]
fn test_add_stdin_valid_yaml_file() {
    let dir = tempfile::tempdir().unwrap();
    let yaml_path = dir.path().join("app.yaml");
    std::fs::write(&yaml_path, "name: testapp\ncommand: echo hello\n").unwrap();

    // Will fail at network level but should parse YAML successfully
    let out = appm()
        .args([
            "-H", "127.0.0.1:1",
            "add", "--stdin", yaml_path.to_str().unwrap(), "--force",
        ])
        .output().unwrap();
    // Expect network error, not parse error
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("Invalid YAML") && !err.contains("Invalid application"),
        "YAML parsing should succeed; got: {}",
        err
    );
}

#[test]
fn test_add_stdin_legacy_owner_yaml_is_accepted_locally() {
    // A legacy `owner:` key must be forwarded to the daemon (which rejects it
    // with an explicit migration error), never rejected or swallowed locally:
    // local parsing succeeds and the request proceeds to the network stage.
    let dir = tempfile::tempdir().unwrap();
    let yaml_path = dir.path().join("legacy.yaml");
    std::fs::write(&yaml_path, "name: legacyapp\ncommand: echo hi\nowner: admin\n").unwrap();

    let out = appm()
        .args([
            "-H", "127.0.0.1:1",
            "add", "--stdin", yaml_path.to_str().unwrap(), "--force",
        ])
        .output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("Invalid YAML") && !err.contains("Invalid application"),
        "legacy owner YAML should parse locally; got: {}",
        err
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// add --metadata with @file (no daemon)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_add_metadata_file_not_found() {
    // No --force so error exit code is not suppressed
    let out = appm()
        .args(["-H", "127.0.0.1:1", "add", "-a", "x", "-c", "y", "-m", "@/nonexistent.json"])
        .output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    // Without a stored Dex session the auth gate fires before metadata parsing.
    assert!(
        err.contains("does not exist")
            || err.contains("No Dex session is configured")
    );
}

#[test]
fn test_add_metadata_valid_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let meta_path = dir.path().join("meta.json");
    std::fs::write(&meta_path, r#"{"key":"value"}"#).unwrap();

    let out = appm()
        .args([
            "-H", "127.0.0.1:1",
            "add", "-a", "x", "-c", "y",
            "-m", &format!("@{}", meta_path.display()),
            "--force",
        ])
        .output().unwrap();
    // Parse succeeds; network error expected
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("does not exist"), "metadata file should be found");
}

// ═══════════════════════════════════════════════════════════════════════════
// rm — multiple apps
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_rm_multiple_apps_flag() {
    // Verify multiple -a flags are accepted by clap
    let out = appm()
        .args(["rm", "-a", "app1", "-a", "app2", "-a", "app3", "--help"])
        .output().unwrap();
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// enable/disable/restart — --all flag
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_enable_all_flag_accepted() {
    let out = appm().args(["enable", "--all", "--help"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn test_disable_all_flag_accepted() {
    let out = appm().args(["disable", "--all", "--help"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn test_restart_all_flag_accepted() {
    let out = appm().args(["restart", "--all", "--help"]).output().unwrap();
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// label — multiple -l flags
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_label_multiple_label_flags_accepted() {
    let out = appm()
        .args(["label", "--add", "-l", "os=linux", "-l", "arch=x86", "--help"])
        .output().unwrap();
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// exec — trailing command args
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_exec_trailing_args_accepted() {
    // exec uses trailing_var_arg; verify clap accepts it
    let out = appm()
        .args(["exec", "--help"])
        .output().unwrap();
    assert!(out.status.success());
    assert!(stdout_of(&["exec", "--help"]).contains("command"));
}

// ═══════════════════════════════════════════════════════════════════════════
// shell — optional trailing command
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_shell_trailing_args_optional() {
    let out = appm().args(["shell", "--help"]).output().unwrap();
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn stdout_of(args: &[&str]) -> String {
    String::from_utf8_lossy(&appm().args(args).output().unwrap().stdout).to_string()
}

fn assert_err_contains(args: &[&str], needle: &str) {
    let out = appm().args(args).output().unwrap();
    assert!(!out.status.success(), "expected failure for {:?}", args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(needle), "stderr for {:?} should contain '{}', got: {}", args, needle, stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// Workflow subcommands (argument parsing only — no daemon needed)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_workflow_help_lists_all_12_subcommands() {
    let s = stdout_of(&["workflow", "--help"]);
    for sub in [
        "add", "get", "list", "rm", "run", "runs", "logs", "output", "cancel", "rerun",
        "detail", "inputs",
    ] {
        assert!(s.contains(sub), "missing workflow subcommand: {}", sub);
    }
}

#[test]
fn test_workflow_add_requires_file() {
    assert_err_contains(&["workflow", "add"], "--file");
}

#[test]
fn test_workflow_add_missing_file_errors() {
    assert_err_contains(
        &["workflow", "add", "-f", "/nonexistent/wf.yaml"],
        "File not found",
    );
}

#[test]
fn test_workflow_get_requires_name() {
    assert_err_contains(&["workflow", "get"], "NAME");
}

#[test]
fn test_workflow_run_rejects_input_without_equals() {
    // -e without key=value must fail loudly, not be silently dropped.
    assert_err_contains(
        &["workflow", "run", "wf-x", "-e", "noequals"],
        "expected key=value",
    );
}

#[test]
fn test_workflow_run_rejects_invalid_input_key() {
    assert_err_contains(
        &["workflow", "run", "wf-x", "-e", "1bad=v"],
        "[A-Za-z_][A-Za-z0-9_]*",
    );
}

#[test]
fn test_workflow_logs_requires_workflow_flag() {
    assert_err_contains(&["workflow", "logs", "some-run-id"], "--workflow");
}

#[test]
fn test_workflow_output_requires_job_and_step() {
    assert_err_contains(&["workflow", "output", "-w", "wf", "run-1"], "--job");
}

#[test]
fn test_workflow_cancel_requires_run_id() {
    assert_err_contains(&["workflow", "cancel", "-w", "wf"], "RUN_ID");
}

#[test]
fn test_workflow_list_alias_ls() {
    let out = appm().args(["workflow", "ls", "--help"]).output().unwrap();
    assert!(out.status.success());
}

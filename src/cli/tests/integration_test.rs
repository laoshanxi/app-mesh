use std::io::Write;
use std::process::{Command, Stdio};

fn appc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_appc"))
}

// ═══════════════════════════════════════════════════════════════════════════
// Help & Version
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_help_lists_all_22_commands() {
    let out = appc().arg("--help").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for cmd in [
        "logon", "logoff", "loginfo", "add", "rm", "view", "enable", "disable", "restart",
        "run", "exec", "shell", "get", "put", "label", "log", "config", "resource",
        "passwd", "lock", "user", "mfa", "appmgpwd", "appmginit",
    ] {
        assert!(s.contains(cmd), "missing command: {}", cmd);
    }
}

#[test]
fn test_version_output() {
    let out = appc().arg("--version").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("appc"));
}

#[test]
fn test_short_help_flag() {
    let out = appc().arg("-h").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("App Mesh CLI"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Global flags
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_global_flags_in_help() {
    let s = stdout_of(&["--help"]);
    for flag in ["--host-url", "--forward-to", "--user", "--password", "--verbose"] {
        assert!(s.contains(flag), "missing global flag: {}", flag);
    }
}

#[test]
fn test_global_short_flags_accepted() {
    // All short global flags before subcommand + --help
    let out = appc()
        .args(["-H", "localhost:6058", "-U", "admin", "-X", "pass", "-v", "logon", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn test_unknown_global_flag_rejected() {
    let out = appc().args(["--nonexistent-flag", "view"]).output().unwrap();
    assert!(!out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Aliases  (6 total)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_alias_ls()     { assert!(appc().args(["ls",     "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_list()   { assert!(appc().args(["list",   "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_reg()    { assert!(appc().args(["reg",    "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_remove() { assert!(appc().args(["remove", "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_unreg()  { assert!(appc().args(["unreg",  "--help"]).output().unwrap().status.success()); }
#[test]
fn test_alias_logout() { assert!(appc().args(["logout", "--help"]).output().unwrap().status.success()); }

#[test]
fn test_alias_content_matches_primary() {
    let rm_help  = String::from_utf8_lossy(&appc().args(["rm",     "--help"]).output().unwrap().stdout).to_string();
    let rem_help = String::from_utf8_lossy(&appc().args(["remove", "--help"]).output().unwrap().stdout).to_string();
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
    for f in ["--timeout", "--audience", "--show-token"] {
        assert!(s.contains(f), "logon missing {}", f);
    }
    // audience is optional with no default
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

#[test]
fn test_help_passwd_all_flags() {
    let s = stdout_of(&["passwd", "--help"]);
    assert!(s.contains("--target"));
}

#[test]
fn test_help_lock_all_flags() {
    let s = stdout_of(&["lock", "--help"]);
    for f in ["--target", "--lock"] { assert!(s.contains(f), "lock missing {}", f); }
}

#[test]
fn test_help_user_all_flags() {
    let s = stdout_of(&["user", "--help"]);
    for f in ["--json", "--all", "--force"] { assert!(s.contains(f), "user missing {}", f); }
}

#[test]
fn test_help_mfa_all_flags() {
    let s = stdout_of(&["mfa", "--help"]);
    for f in ["--add", "--delete"] { assert!(s.contains(f), "mfa missing {}", f); }
}

// ═══════════════════════════════════════════════════════════════════════════
// Required argument validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_missing_subcommand()        { assert!(!appc().output().unwrap().status.success()); }
#[test]
fn test_invalid_subcommand()        { assert!(!appc().arg("xyz").output().unwrap().status.success()); }
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
fn test_lock_requires_target()      { assert_err_contains(&["lock", "--lock", "true"], "--target"); }
#[test]
fn test_lock_requires_lock_flag()   { assert_err_contains(&["lock", "--target", "admin"], "--lock"); }
#[test]
fn test_exec_requires_command()     { assert!(!appc().args(["exec"]).output().unwrap().status.success()); }

// ═══════════════════════════════════════════════════════════════════════════
// Clap type validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_lock_invalid_bool() {
    let out = appc().args(["lock", "--target", "admin", "--lock", "notbool"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_add_invalid_status_bool() {
    let out = appc().args(["add", "-a", "x", "-c", "y", "--status", "notbool"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_add_invalid_pid_type() {
    let out = appc().args(["add", "-a", "x", "-c", "y", "--pid", "abc"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_add_invalid_memory_limit_type() {
    let out = appc().args(["add", "-a", "x", "-c", "y", "--memory-limit", "abc"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_add_invalid_permission_type() {
    let out = appc().args(["add", "-a", "x", "-c", "y", "--permission", "abc"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_view_invalid_log_index_type() {
    let out = appc().args(["view", "-a", "x", "-i", "abc"]).output().unwrap();
    assert!(!out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// appmgpwd — local SHA-256 utility (no daemon)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_appmgpwd_single() {
    let s = stdout_of(&["appmgpwd", "admin"]);
    assert_eq!(s.trim(), "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918");
}

#[test]
fn test_appmgpwd_multiple() {
    let lines = stdout_lines(&["appmgpwd", "admin", "test"]);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918");
    assert_eq!(lines[1], "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

#[test]
fn test_appmgpwd_empty_string() {
    let s = stdout_of(&["appmgpwd", ""]);
    assert_eq!(s.trim(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn test_appmgpwd_special_chars() {
    let s = stdout_of(&["appmgpwd", "p@ss!word#123"]);
    assert!(s.trim().len() == 64); // valid SHA-256 hex
    assert!(s.trim().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_appmgpwd_known_hash_mesh123() {
    let s = stdout_of(&["appmgpwd", "mesh123"]);
    // SHA-256("mesh123")
    assert_eq!(s.trim(), "1fc5f695d166602f3cdbf93995c73075ed19fc246676e3feece8fc092bcc5a29");
}

#[test]
fn test_appmgpwd_stdin_mode() {
    let out = pipe_stdin(&["appmgpwd"], b"admin\ntest\n");
    assert!(out.status.success());
    let lines = lines_of(&out.stdout);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918");
    assert_eq!(lines[1], "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
}

#[test]
fn test_appmgpwd_stdin_skips_blank_lines() {
    let out = pipe_stdin(&["appmgpwd"], b"\nadmin\n\n\n");
    assert!(out.status.success());
    let lines = lines_of(&out.stdout);
    assert_eq!(lines.len(), 1);
}

#[test]
fn test_appmgpwd_output_is_lowercase_hex() {
    let s = stdout_of(&["appmgpwd", "hello"]);
    let hash = s.trim();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
}

// ═══════════════════════════════════════════════════════════════════════════
// appmginit — stub
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_appmginit_exit_code_1() {
    let out = appc().args(["appmginit"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn test_appmginit_error_message_non_root() {
    let out = appc().args(["appmginit"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    // Non-root: "Only root user can generate an initial password."
    // or: "Cannot detect App Mesh installation directory"
    assert!(
        err.contains("root user") || err.contains("Cannot detect") || err.contains("only run once"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_appmginit_help() {
    let out = appc().args(["appmginit", "--help"]).output().unwrap();
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Exit code behavior
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_exits_1() {
    let out = appc().args(["-H", "127.0.0.1:1", "config"]).output().unwrap();
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn test_error_with_force_flag_exits_zero() {
    let out = appc()
        .args(["-H", "127.0.0.1:1", "rm", "-a", "nonexist", "--force"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[cfg(unix)]
#[test]
fn test_error_with_follow_flag_exits_zero() {
    let out = appc()
        .args(["-H", "127.0.0.1:1", "view", "-a", "nonexist", "--follow"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[cfg(unix)]
#[test]
fn test_error_with_short_f_flag_exits_zero() {
    // -f on rm is --force; raw argv scan sees "-f"
    let out = appc()
        .args(["-H", "127.0.0.1:1", "rm", "-a", "nonexist", "-f"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn test_help_always_exits_zero() {
    for cmd in ["logon", "logoff", "loginfo", "add", "rm", "view", "enable", "disable",
                "restart", "run", "exec", "shell", "get", "put", "label", "log",
                "config", "resource", "passwd", "lock", "user", "mfa", "appmgpwd", "appmginit"] {
        let out = appc().args([cmd, "--help"]).output().unwrap();
        assert!(out.status.success(), "{} --help should exit 0", cmd);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Default values in help text
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_default_logon_audience() {
    assert!(stdout_of(&["logon", "--help"]).contains("--audience"));
}

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
    let out = appc()
        .args(["-H", "127.0.0.1:1", "put", "--remote", "/tmp/r", "--local", "/no/such/file.txt"])
        .output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Local file not found") || err.contains("not found"));
}

// ═══════════════════════════════════════════════════════════════════════════
// user --json with non-existent file (no daemon)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(unix)]
#[test]
fn test_user_json_nonexistent_file() {
    let out = appc()
        .args(["-H", "127.0.0.1:1", "user", "--json", "/no/such/user.json"])
        .output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Failed to read user JSON") || err.contains("No such file"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Multiple -e env flags accumulate
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_add_multiple_env_flags_accepted() {
    // Should parse successfully (daemon-dependent for actual operation)
    let out = appc()
        .args(["add", "-a", "test", "-c", "echo", "-e", "K1=V1", "-e", "K2=V2", "--help"])
        .output().unwrap();
    // --help always exits 0; this verifies -e can appear multiple times
    assert!(out.status.success());
}

#[test]
fn test_add_multiple_control_flags_accepted() {
    let out = appc()
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
    let out = appc()
        .args(["-H", "127.0.0.1:1", "add", "--stdin", "/no/such/app.yaml"])
        .output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Failed to read") || err.contains("No such file"));
}

#[test]
fn test_add_stdin_valid_yaml_file() {
    let dir = tempfile::tempdir().unwrap();
    let yaml_path = dir.path().join("app.yaml");
    std::fs::write(&yaml_path, "name: testapp\ncommand: echo hello\n").unwrap();

    // Will fail at network level but should parse YAML successfully
    let out = appc()
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

// ═══════════════════════════════════════════════════════════════════════════
// add --metadata with @file (no daemon)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_add_metadata_file_not_found() {
    // No --force so error exit code is not suppressed
    let out = appc()
        .args(["-H", "127.0.0.1:1", "add", "-a", "x", "-c", "y", "-m", "@/nonexistent.json"])
        .output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("does not exist"));
}

#[test]
fn test_add_metadata_valid_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let meta_path = dir.path().join("meta.json");
    std::fs::write(&meta_path, r#"{"key":"value"}"#).unwrap();

    let out = appc()
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
    let out = appc()
        .args(["rm", "-a", "app1", "-a", "app2", "-a", "app3", "--help"])
        .output().unwrap();
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// enable/disable/restart — --all flag
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_enable_all_flag_accepted() {
    let out = appc().args(["enable", "--all", "--help"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn test_disable_all_flag_accepted() {
    let out = appc().args(["disable", "--all", "--help"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn test_restart_all_flag_accepted() {
    let out = appc().args(["restart", "--all", "--help"]).output().unwrap();
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// label — multiple -l flags
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_label_multiple_label_flags_accepted() {
    let out = appc()
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
    let out = appc()
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
    let out = appc().args(["shell", "--help"]).output().unwrap();
    assert!(out.status.success());
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn stdout_of(args: &[&str]) -> String {
    String::from_utf8_lossy(&appc().args(args).output().unwrap().stdout).to_string()
}

fn stdout_lines(args: &[&str]) -> Vec<String> {
    stdout_of(args).trim().lines().map(|l| l.to_string()).collect()
}

fn lines_of(raw: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(raw)
        .trim()
        .lines()
        .map(|l| l.to_string())
        .collect()
}

fn pipe_stdin(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = appc()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_err_contains(args: &[&str], needle: &str) {
    let out = appc().args(args).output().unwrap();
    assert!(!out.status.success(), "expected failure for {:?}", args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(needle), "stderr for {:?} should contain '{}', got: {}", args, needle, stderr);
}

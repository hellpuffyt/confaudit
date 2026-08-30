//! End-to-end CLI tests: invoke the compiled `confaudit` binary against the
//! fixtures in `testdata/` and check exit codes / output shape.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_confaudit"))
}

#[test]
fn bad_sshd_config_exits_nonzero_and_lists_findings() {
    let out = bin()
        .arg("testdata/sshd/bad_sshd_config")
        .output()
        .expect("run confaudit");
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SSHD001"));
}

#[test]
fn good_sshd_config_still_reports_low_severity_findings_by_default() {
    // Even the hardened fixture is not flagged for anything above 'high',
    // so filtering to that threshold should produce zero findings.
    let out = bin()
        .args(["--severity", "high", "testdata/sshd/good_sshd_config"])
        .output()
        .expect("run confaudit");
    assert!(out.status.success());
}

#[test]
fn bad_nginx_conf_exits_nonzero() {
    let out = bin()
        .arg("testdata/nginx/bad.conf")
        .output()
        .expect("run confaudit");
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("NGX001"));
}

#[test]
fn good_nginx_conf_high_threshold_clean() {
    let out = bin()
        .args(["--severity", "high", "testdata/nginx/good.conf"])
        .output()
        .expect("run confaudit");
    assert!(out.status.success());
}

#[test]
fn bad_dockerfile_exits_nonzero() {
    let out = bin()
        .arg("testdata/docker/Dockerfile.bad")
        .output()
        .expect("run confaudit");
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DOCK004"));
}

#[test]
fn json_output_is_valid_json() {
    let out = bin()
        .args(["--format", "json", "testdata/docker/Dockerfile.bad"])
        .output()
        .expect("run confaudit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert!(parsed["findings"].is_array());
}

#[test]
fn sarif_output_is_valid_json_with_expected_shape() {
    let out = bin()
        .args(["--format", "sarif", "testdata/nginx/bad.conf"])
        .output()
        .expect("run confaudit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(parsed["version"], "2.1.0");
}

#[test]
fn ignore_flag_suppresses_rule() {
    let out = bin()
        .args([
            "--ignore",
            "SSHD001",
            "--severity",
            "critical",
            "testdata/sshd/bad_sshd_config",
        ])
        .output()
        .expect("run confaudit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("SSHD001"));
}

#[test]
fn no_fail_flag_forces_zero_exit() {
    let out = bin()
        .args(["--no-fail", "testdata/sshd/bad_sshd_config"])
        .output()
        .expect("run confaudit");
    assert!(out.status.success());
}

#[test]
fn unrecognized_file_reports_error_and_exit_2() {
    let out = bin().arg("Cargo.toml").output().expect("run confaudit");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_file_argument_shows_usage_error() {
    let out = bin().output().expect("run confaudit");
    assert!(!out.status.success());
}

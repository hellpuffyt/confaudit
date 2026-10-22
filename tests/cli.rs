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

/// Rule IDs reported for a fixture, as a sorted set.
fn rule_ids(path: &str) -> Vec<String> {
    let out = bin()
        .args(["--format", "json", "--no-fail", path])
        .output()
        .expect("run confaudit");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let mut ids: Vec<String> = v["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| f["rule_id"].as_str().expect("rule_id").to_string())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn corpus_of_known_false_positives_and_negatives() {
    // Each fixture reproduces a defect found in the production-readiness
    // audit; the comment is what the previous release reported instead.
    let cases: &[(&str, &[&str])] = &[
        // was []: add_header inheritance and the off-by-slash alias missed
        (
            "testdata/corpus/inheritance_trap.conf",
            &["NGX006", "NGX007", "NGX012"],
        ),
        // was [DOCK002]: `FROM build` and `--platform=` taken for untagged images
        ("testdata/corpus/Dockerfile.multistage-good", &[]),
        // was []: USER in the build stage counted for the final image
        ("testdata/corpus/Dockerfile.multistage-root", &["DOCK001"]),
        // was [SSHD001 (as unset, medium), SSHD006, SSHD007]
        ("testdata/corpus/equals_sshd_config", &["SSHD001"]),
    ];
    for (path, expected) in cases {
        assert_eq!(rule_ids(path), *expected, "{path}");
    }
}

#[test]
fn good_fixtures_are_clean_at_every_severity() {
    for path in [
        "testdata/nginx/good.conf",
        "testdata/docker/Dockerfile.good",
        "testdata/corpus/Dockerfile.multistage-good",
    ] {
        assert_eq!(rule_ids(path), Vec::<String>::new(), "{path}");
    }
}

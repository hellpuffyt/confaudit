//! Library crate for confaudit: audits nginx, sshd, and Dockerfile
//! configuration files for settings that weaken security.
//!
//! Split out from `main.rs` so the parsers, rule sets and output formatters
//! can be exercised directly by tests without going through the CLI.

#![forbid(unsafe_code)]

pub mod finding;
pub mod output;
pub mod parsers;

use finding::{Finding, Severity};
use parsers::FileKind;
use std::path::Path;

/// Run the appropriate parser/rule set for `kind` over `content`, tagging
/// findings with `file` (used for display, not for reading from disk again).
///
/// # Errors
/// Returns a human-readable message if the file cannot be parsed at all
/// (malformed input), rather than panicking.
pub fn audit_content(kind: FileKind, file: &str, content: &str) -> Result<Vec<Finding>, String> {
    match kind {
        FileKind::Sshd => parsers::sshd::audit(file, content),
        FileKind::Nginx => parsers::nginx::audit(file, content),
        FileKind::Dockerfile => parsers::dockerfile::audit(file, content),
    }
}

/// Read and audit a file on disk, inferring its kind from the path.
///
/// # Errors
/// Returns an error if the kind cannot be inferred, the file cannot be
/// read, or the content cannot be parsed.
pub fn audit_file(path: &Path) -> Result<Vec<Finding>, String> {
    let kind = FileKind::detect_or_err(path)?;
    let content = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    audit_content(kind, &path.display().to_string(), &content)
}

impl FileKind {
    /// Like [`parsers::detect`] but returns a descriptive error instead of
    /// `None`.
    ///
    /// # Errors
    /// Returns an error describing why the file kind could not be
    /// determined.
    pub fn detect_or_err(path: &Path) -> Result<Self, String> {
        parsers::detect(path).ok_or_else(|| {
            format!(
                "{}: unrecognized config file (expected sshd_config, an nginx *.conf, or a Dockerfile)",
                path.display()
            )
        })
    }
}

/// Filter findings to those at or above `threshold`, and drop any whose
/// rule id is in `ignore`.
#[must_use]
pub fn filter_findings(
    findings: Vec<Finding>,
    threshold: Severity,
    ignore: &[String],
) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| f.severity >= threshold)
        .filter(|f| !ignore.iter().any(|id| id.eq_ignore_ascii_case(&f.rule_id)))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use finding::SourceKind;
    use std::path::PathBuf;

    fn f(id: &str, sev: Severity) -> Finding {
        Finding::new(id, sev, SourceKind::Sshd, "f", 1, "e", "c", "x")
    }

    #[test]
    fn detect_sshd_config() {
        assert_eq!(
            FileKind::detect_or_err(&PathBuf::from("sshd_config")).unwrap(),
            FileKind::Sshd
        );
    }

    #[test]
    fn detect_dockerfile() {
        assert_eq!(
            FileKind::detect_or_err(&PathBuf::from("Dockerfile")).unwrap(),
            FileKind::Dockerfile
        );
        assert_eq!(
            FileKind::detect_or_err(&PathBuf::from("app.dockerfile")).unwrap(),
            FileKind::Dockerfile
        );
    }

    #[test]
    fn detect_nginx_conf() {
        assert_eq!(
            FileKind::detect_or_err(&PathBuf::from("site.conf")).unwrap(),
            FileKind::Nginx
        );
        assert_eq!(
            FileKind::detect_or_err(&PathBuf::from("nginx.conf")).unwrap(),
            FileKind::Nginx
        );
    }

    #[test]
    fn detect_unknown_errors() {
        assert!(FileKind::detect_or_err(&PathBuf::from("readme.txt")).is_err());
    }

    #[test]
    fn filter_by_threshold() {
        let findings = vec![f("A", Severity::Low), f("B", Severity::High)];
        let out = filter_findings(findings, Severity::High, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "B");
    }

    #[test]
    fn filter_by_ignore_list_case_insensitive() {
        let findings = vec![f("SSHD001", Severity::High), f("SSHD002", Severity::High)];
        let out = filter_findings(findings, Severity::Info, &["sshd001".to_string()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "SSHD002");
    }

    #[test]
    fn audit_file_missing_path_errors() {
        let result = audit_file(&PathBuf::from("sshd_config_does_not_exist_anywhere"));
        assert!(result.is_err());
    }
}

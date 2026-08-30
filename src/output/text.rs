//! Human-readable text output.

use crate::finding::Finding;
use std::fmt::Write as _;

#[must_use]
pub fn render(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No findings.\n".to_string();
    }

    let mut out = String::new();
    for f in findings {
        let loc = if f.line == 0 {
            f.file.clone()
        } else {
            format!("{}:{}", f.file, f.line)
        };
        let _ = writeln!(
            out,
            "[{}] {} ({}) - {}",
            f.severity, f.rule_id, f.source, loc
        );
        let _ = writeln!(out, "  found:      {}", f.evidence);
        let _ = writeln!(out, "  consequence: {}", f.consequence);
        let _ = writeln!(out, "  fix:        {}", f.fix);
        out.push('\n');
    }

    let mut counts = [0usize; 5];
    for f in findings {
        counts[f.severity as usize] += 1;
    }
    let _ = writeln!(
        out,
        "Summary: {} finding(s) - critical={} high={} medium={} low={} info={}",
        findings.len(),
        counts[4],
        counts[3],
        counts[2],
        counts[1],
        counts[0]
    );

    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::finding::SourceKind;

    #[test]
    fn empty_findings_prints_no_findings() {
        assert_eq!(render(&[]), "No findings.\n");
    }

    #[test]
    fn renders_rule_id_and_summary() {
        let f = Finding::new(
            "SSHD001",
            crate::finding::Severity::Critical,
            SourceKind::Sshd,
            "sshd_config",
            3,
            "PermitRootLogin yes",
            "attacker gets root",
            "set to no",
        );
        let out = render(&[f]);
        assert!(out.contains("SSHD001"));
        assert!(out.contains("sshd_config:3"));
        assert!(out.contains("Summary: 1 finding(s) - critical=1"));
    }

    #[test]
    fn file_level_finding_has_no_line_suffix() {
        let f = Finding::new(
            "DOCK008",
            crate::finding::Severity::Info,
            SourceKind::Dockerfile,
            "Dockerfile",
            0,
            "(no HEALTHCHECK)",
            "cannot detect hangs",
            "add HEALTHCHECK",
        );
        let out = render(&[f]);
        assert!(out.contains("Dockerfile\n") || out.contains("Dockerfile "));
        assert!(!out.contains("Dockerfile:0"));
    }
}

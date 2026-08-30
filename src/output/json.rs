//! JSON output: a straightforward serialization of the finding list plus a
//! summary count, suitable for machine consumption.

use crate::finding::Finding;
use serde::Serialize;

#[derive(Serialize)]
struct Summary {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

#[derive(Serialize)]
struct Report<'a> {
    findings: &'a [Finding],
    summary: Summary,
}

/// # Errors
/// Returns an error only if serialization itself fails (it should not, for
/// this data shape, but the caller propagates it rather than panicking).
pub fn render(findings: &[Finding]) -> Result<String, serde_json::Error> {
    let mut counts = [0usize; 5];
    for f in findings {
        counts[f.severity as usize] += 1;
    }
    let report = Report {
        findings,
        summary: Summary {
            total: findings.len(),
            info: counts[0],
            low: counts[1],
            medium: counts[2],
            high: counts[3],
            critical: counts[4],
        },
    };
    serde_json::to_string_pretty(&report)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::finding::{Severity, SourceKind};

    #[test]
    fn empty_findings_summary_is_zero() {
        let s = render(&[]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["summary"]["total"], 0);
        assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn counts_by_severity() {
        let findings = vec![
            Finding::new(
                "A",
                Severity::Critical,
                SourceKind::Sshd,
                "f",
                1,
                "e",
                "c",
                "x",
            ),
            Finding::new(
                "B",
                Severity::Critical,
                SourceKind::Sshd,
                "f",
                2,
                "e",
                "c",
                "x",
            ),
            Finding::new("C", Severity::Low, SourceKind::Sshd, "f", 3, "e", "c", "x"),
        ];
        let s = render(&findings).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["summary"]["critical"], 2);
        assert_eq!(v["summary"]["low"], 1);
        assert_eq!(v["summary"]["total"], 3);
    }

    #[test]
    fn preserves_rule_id_and_line() {
        let findings = vec![Finding::new(
            "NGX001",
            Severity::High,
            SourceKind::Nginx,
            "nginx.conf",
            10,
            "autoindex on;",
            "listing exposed",
            "set off",
        )];
        let s = render(&findings).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["findings"][0]["rule_id"], "NGX001");
        assert_eq!(v["findings"][0]["line"], 10);
    }
}

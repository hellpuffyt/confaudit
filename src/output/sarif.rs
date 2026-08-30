//! SARIF 2.1.0 output for GitHub code scanning.

use crate::finding::Finding;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[must_use]
pub fn render(findings: &[Finding]) -> String {
    let mut rules: BTreeMap<&str, Value> = BTreeMap::new();
    for f in findings {
        rules.entry(f.rule_id.as_str()).or_insert_with(|| {
            json!({
                "id": f.rule_id,
                "shortDescription": { "text": f.consequence },
                "help": { "text": f.fix },
            })
        });
    }

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let line = f.line.max(1);
            json!({
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level(),
                "message": { "text": format!("{} | fix: {}", f.consequence, f.fix) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": { "startLine": line }
                    }
                }]
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "confaudit",
                    "informationUri": "https://github.com/hellpuffyt/confaudit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules.into_values().collect::<Vec<_>>(),
                }
            },
            "results": results,
        }]
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::finding::{Finding, Severity, SourceKind};

    #[test]
    fn empty_findings_produces_valid_sarif_shell() {
        let s = render(&[]);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn maps_severity_to_sarif_level() {
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
                Severity::Medium,
                SourceKind::Sshd,
                "f",
                2,
                "e",
                "c",
                "x",
            ),
            Finding::new("C", Severity::Info, SourceKind::Sshd, "f", 3, "e", "c", "x"),
        ];
        let s = render(&findings);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "note");
    }

    #[test]
    fn line_zero_clamped_to_one_for_sarif_region() {
        let findings = vec![Finding::new(
            "DOCK008",
            Severity::Info,
            SourceKind::Dockerfile,
            "Dockerfile",
            0,
            "e",
            "c",
            "x",
        )];
        let s = render(&findings);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            1
        );
    }

    #[test]
    fn rules_deduplicated_by_rule_id() {
        let findings = vec![
            Finding::new(
                "SSHD001",
                Severity::Critical,
                SourceKind::Sshd,
                "a",
                1,
                "e",
                "c",
                "x",
            ),
            Finding::new(
                "SSHD001",
                Severity::Critical,
                SourceKind::Sshd,
                "b",
                2,
                "e",
                "c",
                "x",
            ),
        ];
        let s = render(&findings);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
    }
}

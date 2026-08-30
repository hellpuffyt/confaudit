//! The core `Finding` type shared by every parser and every output format.

use serde::Serialize;
use std::cmp::Ordering;
use std::fmt;

/// How dangerous a finding is. Ordered from least to most severe so that
/// `Severity::Medium < Severity::Critical` etc. and threshold filtering
/// (`--severity`) is a simple comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// SARIF only understands `note`, `warning` and `error`. Map our five
    /// levels down onto those three.
    #[must_use]
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Self::Info | Self::Low => "note",
            Self::Medium => "warning",
            Self::High | Self::Critical => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" | "crit" => Ok(Self::Critical),
            other => Err(format!(
                "invalid severity '{other}' (expected one of: info, low, medium, high, critical)"
            )),
        }
    }
}

/// The kind of configuration file a finding came from. Used by the SARIF
/// writer to pick a stable `ruleId` prefix and by the human formatter to
/// group output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Sshd,
    Nginx,
    Dockerfile,
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Sshd => "sshd",
            Self::Nginx => "nginx",
            Self::Dockerfile => "dockerfile",
        };
        write!(f, "{s}")
    }
}

/// A single security finding produced by a parser/rule pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable identifier, e.g. `SSHD001`. Never renumber once shipped.
    pub rule_id: String,
    pub severity: Severity,
    pub source: SourceKind,
    pub file: String,
    /// 1-based line number. `0` means "file level" (no single line applies).
    pub line: usize,
    /// The offending text as it appears in the file (trimmed).
    pub evidence: String,
    /// What an attacker gains, or what breaks, if this is left as-is.
    pub consequence: String,
    /// The exact fix to apply.
    pub fix: String,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        source: SourceKind,
        file: impl Into<String>,
        line: usize,
        evidence: impl Into<String>,
        consequence: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            source,
            file: file.into(),
            line,
            evidence: evidence.into(),
            consequence: consequence.into(),
            fix: fix.into(),
        }
    }
}

impl PartialOrd for Finding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Finding {
    fn cmp(&self, other: &Self) -> Ordering {
        // Highest severity first, then file, then line, then rule id.
        other
            .severity
            .cmp(&self.severity)
            .then_with(|| self.file.cmp(&other.file))
            .then_with(|| self.line.cmp(&other.line))
            .then_with(|| self.rule_id.cmp(&other.rule_id))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::str::FromStr;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_from_str_valid() {
        assert_eq!(Severity::from_str("critical").unwrap(), Severity::Critical);
        assert_eq!(Severity::from_str("HIGH").unwrap(), Severity::High);
        assert_eq!(Severity::from_str("med").unwrap(), Severity::Medium);
        assert_eq!(Severity::from_str("crit").unwrap(), Severity::Critical);
    }

    #[test]
    fn severity_from_str_invalid() {
        assert!(Severity::from_str("nonsense").is_err());
    }

    #[test]
    fn severity_sarif_level_mapping() {
        assert_eq!(Severity::Info.sarif_level(), "note");
        assert_eq!(Severity::Low.sarif_level(), "note");
        assert_eq!(Severity::Medium.sarif_level(), "warning");
        assert_eq!(Severity::High.sarif_level(), "error");
        assert_eq!(Severity::Critical.sarif_level(), "error");
    }

    #[test]
    fn finding_sorts_by_severity_then_file_then_line() {
        let a = Finding::new("A", Severity::Low, SourceKind::Sshd, "f", 5, "e", "c", "x");
        let b = Finding::new(
            "B",
            Severity::Critical,
            SourceKind::Sshd,
            "f",
            1,
            "e",
            "c",
            "x",
        );
        let mut v = [a.clone(), b.clone()];
        v.sort();
        assert_eq!(v[0], b);
        assert_eq!(v[1], a);
    }
}

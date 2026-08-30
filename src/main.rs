#![forbid(unsafe_code)]

use clap::Parser;
use confaudit::finding::Severity;
use confaudit::output::Format;
use confaudit::{audit_file, filter_findings};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

/// Audit nginx, sshd and Docker configuration files for settings that
/// weaken security.
#[derive(Parser, Debug)]
#[command(name = "confaudit", version, about)]
struct Cli {
    /// Configuration file(s) to audit (`sshd_config`, nginx *.conf, `Dockerfile`).
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Output format: text, json, or sarif.
    #[arg(long, short = 'f', default_value = "text")]
    format: String,

    /// Only report findings at or above this severity: info, low, medium, high, critical.
    #[arg(long, default_value = "info")]
    severity: String,

    /// Comma-separated rule IDs to suppress (e.g. `SSHD001,NGX002`).
    #[arg(long)]
    ignore: Option<String>,

    /// Exit with status 0 even if findings were reported.
    #[arg(long)]
    no_fail: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let format = match Format::from_str(&cli.format) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("confaudit: {e}");
            return ExitCode::from(2);
        }
    };
    let severity = match Severity::from_str(&cli.severity) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("confaudit: {e}");
            return ExitCode::from(2);
        }
    };

    let ignore: Vec<String> = cli
        .ignore
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let mut all_findings = Vec::new();
    let mut had_error = false;

    for path in &cli.paths {
        match audit_file(path) {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => {
                eprintln!("confaudit: {e}");
                had_error = true;
            }
        }
    }

    let findings = filter_findings(all_findings, severity, &ignore);

    let rendered = match format {
        Format::Text => confaudit::output::text::render(&findings),
        Format::Json => match confaudit::output::json::render(&findings) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("confaudit: failed to render JSON: {e}");
                return ExitCode::from(2);
            }
        },
        Format::Sarif => confaudit::output::sarif::render(&findings),
    };
    println!("{rendered}");

    if had_error {
        return ExitCode::from(2);
    }
    if !cli.no_fail && !findings.is_empty() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

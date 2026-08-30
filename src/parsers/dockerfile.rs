//! Parser and rule set for `Dockerfile`s.
//!
//! Dockerfiles are line-oriented (`INSTRUCTION args...`) with backslash line
//! continuation and `#` comments. This is a real instruction parser (it
//! joins continuations, tracks the starting line of each instruction, and
//! ignores comments) rather than a bag of regexes over raw text.

use crate::finding::{Finding, Severity, SourceKind};

#[derive(Debug, Clone)]
pub struct Instruction {
    pub keyword: String,
    pub args: String,
    pub line: usize,
    pub raw: String,
}

/// Parse a Dockerfile into instructions, joining backslash-continued lines
/// and recording the line number the instruction started on.
///
/// # Errors
/// Returns an error if a line continuation has no following line, or an
/// instruction line is empty after trimming.
pub fn parse(content: &str) -> Result<Vec<Instruction>, String> {
    let mut instructions = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0usize;

    while i < lines.len() {
        let start_line = i + 1;
        let mut raw_line = lines[i].to_string();
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }

        // Join backslash-continued lines.
        let mut joined = raw_line.trim_end().to_string();
        while joined.ends_with('\\') {
            joined.pop();
            i += 1;
            if i >= lines.len() {
                return Err(format!(
                    "line {start_line}: line continuation ('\\\\') with no following line"
                ));
            }
            joined.push(' ');
            joined.push_str(lines[i].trim());
            let cont = joined.trim_end();
            joined = cont.to_string();
        }
        raw_line = joined;

        let trimmed = raw_line.trim();
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let keyword = parts.next().unwrap_or_default().to_ascii_uppercase();
        let args = parts.next().unwrap_or("").trim().to_string();

        if keyword.is_empty() {
            return Err(format!("line {start_line}: empty instruction"));
        }

        instructions.push(Instruction {
            keyword,
            args,
            line: start_line,
            raw: trimmed.to_string(),
        });
        i += 1;
    }

    Ok(instructions)
}

const SECRET_KEY_HINTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "accesskey",
    "private_key",
    "privatekey",
    "auth_token",
    "client_secret",
];

fn env_arg_pairs(args: &str) -> Vec<(String, String)> {
    // ENV/ARG support "KEY=VALUE KEY2=VALUE2" and legacy "KEY VALUE" forms.
    let mut pairs = Vec::new();
    if args.contains('=') {
        for token in split_respecting_quotes(args) {
            if let Some((k, v)) = token.split_once('=') {
                pairs.push((
                    k.to_string(),
                    v.trim_matches('"').trim_matches('\'').to_string(),
                ));
            }
        }
    } else {
        let mut it = args.splitn(2, char::is_whitespace);
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            pairs.push((k.to_string(), v.trim().to_string()));
        }
    }
    pairs
}

fn split_respecting_quotes(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut quote = '"';
    for c in s.chars() {
        match c {
            '"' | '\'' if !in_quotes => {
                in_quotes = true;
                quote = c;
                cur.push(c);
            }
            c2 if in_quotes && c2 == quote => {
                in_quotes = false;
                cur.push(c2);
            }
            c2 if c2.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c2 => cur.push(c2),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn mk(
    rule_id: &str,
    severity: Severity,
    file: &str,
    line: usize,
    evidence: &str,
    consequence: &str,
    fix: &str,
) -> Finding {
    Finding::new(
        rule_id,
        severity,
        SourceKind::Dockerfile,
        file,
        line,
        evidence,
        consequence,
        fix,
    )
}

/// Parse and audit `content`, returning every rule violation found.
///
/// # Errors
/// Returns an error if `content` cannot be parsed (see [`parse`]).
#[allow(clippy::too_many_lines)]
pub fn audit(file: &str, content: &str) -> Result<Vec<Finding>, String> {
    let instructions = parse(content)?;
    let mut findings = Vec::new();

    // DOCK001: no USER directive, or last USER is root.
    let mut last_user: Option<&Instruction> = None;
    for ins in &instructions {
        if ins.keyword == "USER" {
            last_user = Some(ins);
        }
    }
    match last_user {
        None => findings.push(mk(
            "DOCK001",
            Severity::High,
            file,
            0,
            "(no USER instruction)",
            "The container runs as root by default. A compromise of the containerized process (e.g. via a code injection bug) grants the attacker root inside the container and a much shorter path to breaking out to the host.",
            "Add a non-root user and switch to it, e.g. 'RUN useradd -m app' then 'USER app'.",
        )),
        Some(ins) => {
            let user = ins.args.split(':').next().unwrap_or("").trim();
            if user == "root" || user == "0" {
                findings.push(mk(
                    "DOCK001",
                    Severity::High,
                    file,
                    ins.line,
                    &ins.raw,
                    "The container explicitly runs as root. A compromise of the containerized process grants the attacker root inside the container and a much shorter path to breaking out to the host.",
                    "Create and switch to a non-root user, e.g. 'RUN useradd -m app' then 'USER app'.",
                ));
            }
        }
    }

    // DOCK008: missing HEALTHCHECK.
    if !instructions.iter().any(|i| i.keyword == "HEALTHCHECK") {
        findings.push(mk(
            "DOCK008",
            Severity::Info,
            file,
            0,
            "(no HEALTHCHECK instruction)",
            "Without a HEALTHCHECK, orchestrators cannot detect that the process inside the container has hung or is unresponsive, so traffic keeps being routed to a dead instance.",
            "Add a HEALTHCHECK instruction, e.g. 'HEALTHCHECK CMD curl -f http://localhost/health || exit 1'.",
        ));
    }

    let mut first_dependency_install: Option<usize> = None;
    let mut copy_all_line: Option<usize> = None;

    for ins in &instructions {
        match ins.keyword.as_str() {
            "FROM" => {
                let image = ins.args.split_whitespace().next().unwrap_or("");
                let image_no_platform = image;
                if !image_no_platform.contains("scratch") {
                    let tag_part = image_no_platform
                        .rsplit('/')
                        .next()
                        .unwrap_or(image_no_platform);
                    if !tag_part.contains(':') {
                        findings.push(mk(
                            "DOCK002",
                            Severity::Medium,
                            file,
                            ins.line,
                            &ins.raw,
                            "No tag means Docker resolves ':latest' at build time, so the exact base image contents are not reproducible and can silently change (including picking up new vulnerabilities) between builds.",
                            "Pin an explicit version tag, e.g. 'FROM debian:12.5' (ideally pin by digest for full reproducibility).",
                        ));
                    } else if tag_part.ends_with(":latest") {
                        findings.push(mk(
                            "DOCK002",
                            Severity::Medium,
                            file,
                            ins.line,
                            &ins.raw,
                            "':latest' is a moving target: the exact base image contents are not reproducible and can silently change (including picking up new vulnerabilities) between builds.",
                            "Pin an explicit version tag, e.g. 'FROM debian:12.5' (ideally pin by digest for full reproducibility).",
                        ));
                    }
                }
            }
            "ADD" => {
                let lower = ins.args.to_ascii_lowercase();
                if lower.contains("http://") || lower.contains("https://") {
                    findings.push(mk(
                        "DOCK003",
                        Severity::Medium,
                        file,
                        ins.line,
                        &ins.raw,
                        "ADD fetches the URL with no integrity check and unpacks archives automatically; a compromised or MITM'd URL can inject arbitrary files into the image without any verification step.",
                        "Use 'RUN curl -fsSL <url> -o file && sha256sum -c ...' (or COPY a locally vetted file) so the download is checksummed.",
                    ));
                }
            }
            "ENV" | "ARG" => {
                for (key, value) in env_arg_pairs(&ins.args) {
                    let key_lower = key.to_ascii_lowercase();
                    let looks_like_secret = SECRET_KEY_HINTS.iter().any(|h| key_lower.contains(h));
                    let value_nonempty = !value.trim().is_empty();
                    if looks_like_secret && value_nonempty {
                        findings.push(mk(
                            "DOCK004",
                            Severity::Critical,
                            file,
                            ins.line,
                            &ins.raw,
                            "Values baked into ENV/ARG are permanently embedded in the image layer history and readable via 'docker history'/'docker inspect' by anyone with pull access, even after a later layer removes them.",
                            "Pass the secret at runtime (env var, mounted file, or orchestrator secret store) or use a BuildKit '--mount=type=secret', never ENV/ARG.",
                        ));
                    }
                }
            }
            "RUN" => {
                let lower = ins.args.to_ascii_lowercase();
                if lower.contains("apt-get install") || lower.contains("apt install") {
                    let no_recommends = lower.contains("--no-install-recommends");
                    let cleans = lower.contains("rm -rf /var/lib/apt/lists")
                        || lower.contains("apt-get clean");
                    if !no_recommends || !cleans {
                        let missing = match (no_recommends, cleans) {
                            (false, false) => "'--no-install-recommends' and apt list cleanup",
                            (false, true) => "'--no-install-recommends'",
                            (true, false) => "apt list cleanup ('rm -rf /var/lib/apt/lists/*')",
                            (true, true) => unreachable!(),
                        };
                        findings.push(mk(
                            "DOCK005",
                            Severity::Low,
                            file,
                            ins.line,
                            &ins.raw,
                            &format!("Missing {missing}: this pulls in extra packages and leaves apt's package index cached in the image layer, growing the attack surface (more installed software) and image size unnecessarily."),
                            "Use 'apt-get install -y --no-install-recommends <pkgs> && rm -rf /var/lib/apt/lists/*' in the same RUN layer.",
                        ));
                    }
                }
                if (lower.contains("curl") || lower.contains("wget"))
                    && (lower.contains("| sh")
                        || lower.contains("|sh")
                        || lower.contains("| bash")
                        || lower.contains("|bash"))
                {
                    findings.push(mk(
                        "DOCK006",
                        Severity::High,
                        file,
                        ins.line,
                        &ins.raw,
                        "Piping a remote download straight into a shell executes whatever that server returns with no integrity check or review; a compromised endpoint or MITM gives an attacker arbitrary code execution during the build.",
                        "Download to a file, verify its checksum/signature, then execute it, e.g. 'curl -fsSL url -o install.sh && sha256sum -c install.sh.sha256 && sh install.sh'.",
                    ));
                }
                if lower.contains("--privileged") {
                    findings.push(mk(
                        "DOCK007",
                        Severity::High,
                        file,
                        ins.line,
                        &ins.raw,
                        "A '--privileged' reference inside the build suggests the resulting image expects (or was tested with) full host device/capability access, which effectively disables container isolation for anything using it.",
                        "Avoid requiring '--privileged'; grant only the specific capabilities needed via '--cap-add'.",
                    ));
                }
                if lower.split_whitespace().any(|w| w == "sudo") {
                    findings.push(mk(
                        "DOCK009",
                        Severity::Low,
                        file,
                        ins.line,
                        &ins.raw,
                        "'sudo' inside a build step is redundant (build steps already run as root by default) and if it lingers into the runtime image it lets a non-root USER trivially regain root.",
                        "Remove 'sudo'; run the command directly as root during build, and if a non-root runtime user needs elevated actions, grant a narrow, explicit mechanism instead.",
                    ));
                }
                if (lower.contains("install") || lower.contains("download"))
                    && first_dependency_install.is_none()
                {
                    first_dependency_install = Some(ins.line);
                }
            }
            "COPY" => {
                let a = ins.args.trim();
                if (a == ". ." || a.starts_with(". . ") || a == "./ ./") && copy_all_line.is_none()
                {
                    copy_all_line = Some(ins.line);
                }
            }
            _ => {}
        }
    }

    // DOCK010: COPY . . before the dependency install step busts the layer
    // cache on every source change, forcing a full reinstall each build.
    if let (Some(copy_line), Some(install_line)) = (copy_all_line, first_dependency_install) {
        if copy_line < install_line {
            findings.push(mk(
                "DOCK010",
                Severity::Info,
                file,
                copy_line,
                "COPY . .",
                "Copying the entire build context before installing dependencies invalidates Docker's layer cache on every source-code change, forcing a full dependency reinstall on nearly every build.",
                "Copy only the dependency manifest first (e.g. 'COPY package.json .'), run the install, then 'COPY . .' for the rest of the source.",
            ));
        }
    }

    findings.sort();
    Ok(findings)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn has(findings: &[Finding], id: &str) -> bool {
        findings.iter().any(|f| f.rule_id == id)
    }

    #[test]
    fn no_user_flagged() {
        let f = audit("Dockerfile", "FROM debian:12\n").unwrap();
        assert!(has(&f, "DOCK001"));
    }

    #[test]
    fn user_root_flagged() {
        let f = audit("Dockerfile", "FROM debian:12\nUSER root\n").unwrap();
        assert!(has(&f, "DOCK001"));
    }

    #[test]
    fn user_zero_flagged() {
        let f = audit("Dockerfile", "FROM debian:12\nUSER 0\n").unwrap();
        assert!(has(&f, "DOCK001"));
    }

    #[test]
    fn user_nonroot_clean() {
        let f = audit("Dockerfile", "FROM debian:12\nUSER app\n").unwrap();
        assert!(!has(&f, "DOCK001"));
    }

    #[test]
    fn latest_tag_flagged() {
        let f = audit("Dockerfile", "FROM debian:latest\nUSER app\n").unwrap();
        assert!(has(&f, "DOCK002"));
    }

    #[test]
    fn no_tag_flagged() {
        let f = audit("Dockerfile", "FROM debian\nUSER app\n").unwrap();
        assert!(has(&f, "DOCK002"));
    }

    #[test]
    fn pinned_tag_clean() {
        let f = audit("Dockerfile", "FROM debian:12.5\nUSER app\n").unwrap();
        assert!(!has(&f, "DOCK002"));
    }

    #[test]
    fn scratch_base_clean() {
        let f = audit("Dockerfile", "FROM scratch\nUSER app\n").unwrap();
        assert!(!has(&f, "DOCK002"));
    }

    #[test]
    fn add_url_flagged() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nADD https://example.com/file.tar.gz /tmp/\nUSER app\n",
        )
        .unwrap();
        assert!(has(&f, "DOCK003"));
    }

    #[test]
    fn add_local_file_clean() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nADD app.tar.gz /tmp/\nUSER app\n",
        )
        .unwrap();
        assert!(!has(&f, "DOCK003"));
    }

    #[test]
    fn copy_instead_of_add_clean() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nCOPY app.tar.gz /tmp/\nUSER app\n",
        )
        .unwrap();
        assert!(!has(&f, "DOCK003"));
    }

    #[test]
    fn secret_in_env_flagged() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nENV DB_PASSWORD=hunter2fake\nUSER app\n",
        )
        .unwrap();
        assert!(has(&f, "DOCK004"));
    }

    #[test]
    fn secret_in_arg_flagged() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nARG API_KEY=fake-abc123\nUSER app\n",
        )
        .unwrap();
        assert!(has(&f, "DOCK004"));
    }

    #[test]
    fn non_secret_env_clean() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nENV APP_ENV=production\nUSER app\n",
        )
        .unwrap();
        assert!(!has(&f, "DOCK004"));
    }

    #[test]
    fn empty_secret_value_not_flagged() {
        let f = audit("Dockerfile", "FROM debian:12\nARG DB_PASSWORD\nUSER app\n").unwrap();
        assert!(!has(&f, "DOCK004"));
    }

    #[test]
    fn apt_install_missing_flags_flagged() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nRUN apt-get update && apt-get install -y curl\nUSER app\n",
        )
        .unwrap();
        assert!(has(&f, "DOCK005"));
    }

    #[test]
    fn apt_install_clean_flags_clean() {
        let cfg = "FROM debian:12\nRUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\nUSER app\n";
        let f = audit("Dockerfile", cfg).unwrap();
        assert!(!has(&f, "DOCK005"));
    }

    #[test]
    fn curl_pipe_sh_flagged() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nRUN curl -fsSL https://get.example.com | sh\nUSER app\n",
        )
        .unwrap();
        assert!(has(&f, "DOCK006"));
    }

    #[test]
    fn curl_pipe_bash_flagged() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nRUN curl -fsSL https://get.example.com | bash\nUSER app\n",
        )
        .unwrap();
        assert!(has(&f, "DOCK006"));
    }

    #[test]
    fn curl_to_file_clean() {
        let cfg = "FROM debian:12\nRUN curl -fsSL https://get.example.com -o install.sh && sh install.sh\nUSER app\n";
        let f = audit("Dockerfile", cfg).unwrap();
        assert!(!has(&f, "DOCK006"));
    }

    #[test]
    fn privileged_hint_flagged() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nRUN echo 'requires --privileged' > /README\nUSER app\n",
        )
        .unwrap();
        assert!(has(&f, "DOCK007"));
    }

    #[test]
    fn no_privileged_hint_clean() {
        let f = audit("Dockerfile", "FROM debian:12\nRUN echo hello\nUSER app\n").unwrap();
        assert!(!has(&f, "DOCK007"));
    }

    #[test]
    fn missing_healthcheck_flagged() {
        let f = audit("Dockerfile", "FROM debian:12\nUSER app\n").unwrap();
        assert!(has(&f, "DOCK008"));
    }

    #[test]
    fn healthcheck_present_clean() {
        let cfg = "FROM debian:12\nUSER app\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n";
        let f = audit("Dockerfile", cfg).unwrap();
        assert!(!has(&f, "DOCK008"));
    }

    #[test]
    fn sudo_usage_flagged() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nRUN sudo apt-get update\nUSER app\n",
        )
        .unwrap();
        assert!(has(&f, "DOCK009"));
    }

    #[test]
    fn no_sudo_clean() {
        let f = audit(
            "Dockerfile",
            "FROM debian:12\nRUN apt-get update\nUSER app\n",
        )
        .unwrap();
        assert!(!has(&f, "DOCK009"));
    }

    #[test]
    fn copy_all_before_install_flagged() {
        let cfg = "FROM node:20.11\nWORKDIR /app\nCOPY . .\nRUN npm install\nUSER app\n";
        let f = audit("Dockerfile", cfg).unwrap();
        assert!(has(&f, "DOCK010"));
    }

    #[test]
    fn copy_manifest_then_install_then_copy_all_clean() {
        let cfg = "FROM node:20.11\nWORKDIR /app\nCOPY package.json .\nRUN npm install\nCOPY . .\nUSER app\n";
        let f = audit("Dockerfile", cfg).unwrap();
        assert!(!has(&f, "DOCK010"));
    }

    #[test]
    fn line_continuation_joins_instruction() {
        let cfg = "FROM debian:12\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends curl && \\\n    rm -rf /var/lib/apt/lists/*\nUSER app\n";
        let instructions = parse(cfg).unwrap();
        let run = instructions
            .iter()
            .find(|i| i.keyword == "RUN")
            .expect("RUN present");
        assert!(run.args.contains("curl"));
        assert!(run.args.contains("rm -rf"));
    }

    #[test]
    fn comments_are_ignored() {
        let cfg = "# comment\nFROM debian:12\n# another comment\nUSER app\n";
        let instructions = parse(cfg).unwrap();
        assert_eq!(instructions.len(), 2);
    }

    #[test]
    fn line_number_accuracy() {
        let cfg = "FROM debian:12\nUSER app\nRUN echo hi\nRUN sudo echo bye\n";
        let f = audit("Dockerfile", cfg).unwrap();
        let finding = f.iter().find(|x| x.rule_id == "DOCK009").expect("present");
        assert_eq!(finding.line, 4);
    }

    #[test]
    fn unterminated_continuation_errors_cleanly() {
        let cfg = "FROM debian:12\nRUN echo hi \\\n";
        let result = parse(cfg);
        assert!(result.is_err());
    }

    #[test]
    fn empty_file_flags_missing_user_and_healthcheck() {
        let f = audit("Dockerfile", "").unwrap();
        assert!(has(&f, "DOCK001"));
        assert!(has(&f, "DOCK008"));
    }

    #[test]
    fn env_multiple_key_value_pairs_parsed() {
        let cfg = "FROM debian:12\nENV FOO=bar BAR=baz\nUSER app\n";
        let f = audit("Dockerfile", cfg).unwrap();
        assert!(!has(&f, "DOCK004"));
    }
}

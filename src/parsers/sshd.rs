//! Parser and rule set for `sshd_config`.
//!
//! `sshd_config` is a simple keyword/argument-per-line format, but it has one
//! wrinkle that trips up naive line-by-line scanners: a `Match` block scopes
//! every directive that follows it (until the next `Match` or end of file) to
//! a condition (user, group, address, etc). A directive inside a `Match`
//! block is *not* a global setting and must not be reported as one.

use crate::finding::{Finding, Severity, SourceKind};

/// One parsed directive: keyword (lower-cased), raw argument string, the
/// 1-based line it came from, and whether it sits inside a `Match` block.
#[derive(Debug, Clone)]
struct Directive {
    keyword: String,
    args: String,
    line: usize,
    raw: String,
    in_match: bool,
}

/// Parse the raw text of an `sshd_config` file into directives, correctly
/// tracking `Match` scope. Returns an error for input that cannot be
/// tokenized at all (e.g. an unterminated quote), instead of panicking.
fn parse(content: &str) -> Result<Vec<Directive>, String> {
    let mut directives = Vec::new();
    let mut in_match = false;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Reject an unterminated quote rather than silently mis-splitting.
        if trimmed.matches('"').count() % 2 != 0 {
            return Err(format!("line {line_no}: unterminated quoted string"));
        }

        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let keyword_raw = parts.next().unwrap_or_default();
        let keyword = keyword_raw.to_ascii_lowercase();
        let args = parts.next().unwrap_or("").trim().to_string();

        if keyword == "match" {
            // Any Match line (including "Match all") opens a new conditional
            // scope for everything that follows.
            in_match = true;
            directives.push(Directive {
                keyword,
                args,
                line: line_no,
                raw: trimmed.to_string(),
                in_match,
            });
            continue;
        }

        directives.push(Directive {
            keyword,
            args,
            line: line_no,
            raw: trimmed.to_string(),
            in_match,
        });
    }

    Ok(directives)
}

/// Strip a `#` comment, respecting a `#` inside double quotes.
fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..i],
            _ => {}
        }
    }
    line
}

fn yes(args: &str) -> bool {
    args.trim().eq_ignore_ascii_case("yes")
}

const WEAK_CIPHERS: &[&str] = &[
    "3des-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
];

const WEAK_MACS: &[&str] = &[
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1-96",
    "hmac-ripemd160",
    "umac-64@openssh.com",
];

const WEAK_KEX: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
];

fn list_has_weak(args: &str, weak: &[&str]) -> Vec<String> {
    let list = args.trim_start_matches(['+', '-', '^']);
    list.split(',')
        .map(str::trim)
        .filter(|a| weak.iter().any(|w| w.eq_ignore_ascii_case(a)))
        .map(str::to_string)
        .collect()
}

/// Audit the parsed directives, emitting one finding per violated rule.
/// `in_match` directives are intentionally excluded from all global checks.
///
/// # Errors
/// Returns an error if `content` cannot be parsed (see [`parse`]).
#[allow(clippy::too_many_lines)]
pub fn audit(file: &str, content: &str) -> Result<Vec<Finding>, String> {
    let directives = parse(content)?;
    let mut findings = Vec::new();

    let global = || directives.iter().filter(|d| !d.in_match);
    let find_global = |kw: &str| global().find(|d| d.keyword == kw);

    let f = |rule_id: &str,
             sev: Severity,
             line: usize,
             evidence: &str,
             consequence: &str,
             fix: &str| {
        Finding::new(
            rule_id,
            sev,
            SourceKind::Sshd,
            file,
            line,
            evidence,
            consequence,
            fix,
        )
    };

    // SSHD001: PermitRootLogin yes / without-password
    if let Some(d) = find_global("permitrootlogin") {
        let arg = d.args.to_ascii_lowercase();
        if arg == "yes" {
            findings.push(f(
                "SSHD001",
                Severity::Critical,
                d.line,
                &d.raw,
                "An attacker who obtains or brute-forces any valid credential (password or key) can log in directly as root, skipping privilege escalation entirely.",
                "Set 'PermitRootLogin no' and use sudo with a named account for administrative access.",
            ));
        } else if arg == "without-password" || arg == "prohibit-password" {
            findings.push(f(
                "SSHD002",
                Severity::High,
                d.line,
                &d.raw,
                "Root login is still permitted via public key. A stolen or weakly-protected root private key grants full root access with no additional factor.",
                "Set 'PermitRootLogin no' and use sudo with a named account for administrative access.",
            ));
        }
    } else {
        findings.push(f(
            "SSHD001",
            Severity::Medium,
            0,
            "(PermitRootLogin not set)",
            "OpenSSH defaults to 'prohibit-password', which still allows direct root key login. Root logins are unaudited and bypass per-user accountability.",
            "Add 'PermitRootLogin no' explicitly.",
        ));
    }

    // SSHD003: PasswordAuthentication yes
    if let Some(d) = find_global("passwordauthentication") {
        if yes(&d.args) {
            findings.push(f(
                "SSHD003",
                Severity::High,
                d.line,
                &d.raw,
                "Passwords are guessable and phishable; enabling password auth exposes the server to credential-stuffing and brute-force login attempts.",
                "Set 'PasswordAuthentication no' and rely on key-based or certificate-based authentication.",
            ));
        }
    }

    // SSHD004: PermitEmptyPasswords yes
    if let Some(d) = find_global("permitemptypasswords") {
        if yes(&d.args) {
            findings.push(f(
                "SSHD004",
                Severity::Critical,
                d.line,
                &d.raw,
                "Any account with a blank password can be logged into by anyone, with no credential needed at all.",
                "Set 'PermitEmptyPasswords no'.",
            ));
        }
    }

    // SSHD005: Protocol 1
    if let Some(d) = find_global("protocol") {
        if d.args.split(',').any(|p| p.trim() == "1") {
            findings.push(f(
                "SSHD005",
                Severity::Critical,
                d.line,
                &d.raw,
                "SSH protocol 1 has known cryptographic weaknesses (including trivial MITM attacks) and has been removed from modern OpenSSH entirely.",
                "Remove the Protocol directive (or set 'Protocol 2') so only SSHv2 is used.",
            ));
        }
    }

    // SSHD006/007/008: weak Ciphers/MACs/KexAlgorithms
    if let Some(d) = find_global("ciphers") {
        let weak = list_has_weak(&d.args, WEAK_CIPHERS);
        if !weak.is_empty() {
            findings.push(f(
                "SSHD006",
                Severity::High,
                d.line,
                &d.raw,
                &format!(
                    "Weak/legacy cipher(s) enabled ({}); CBC-mode and RC4 ciphers are vulnerable to known plaintext-recovery attacks.",
                    weak.join(", ")
                ),
                "Restrict Ciphers to AEAD ciphers, e.g. 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com'.",
            ));
        }
    }
    if let Some(d) = find_global("macs") {
        let weak = list_has_weak(&d.args, WEAK_MACS);
        if !weak.is_empty() {
            findings.push(f(
                "SSHD007",
                Severity::High,
                d.line,
                &d.raw,
                &format!(
                    "Weak MAC(s) enabled ({}); MD5/SHA1-96/truncated MACs are vulnerable to collision and forgery attacks that can allow traffic tampering.",
                    weak.join(", ")
                ),
                "Restrict MACs to ETM/SHA2 variants, e.g. 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com'.",
            ));
        }
    }
    if let Some(d) = find_global("kexalgorithms") {
        let weak = list_has_weak(&d.args, WEAK_KEX);
        if !weak.is_empty() {
            findings.push(f(
                "SSHD008",
                Severity::High,
                d.line,
                &d.raw,
                &format!(
                    "Weak key exchange algorithm(s) enabled ({}); SHA-1-based and small DH groups are vulnerable to Logjam-style attacks that weaken forward secrecy.",
                    weak.join(", ")
                ),
                "Restrict KexAlgorithms to modern groups, e.g. 'KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512'.",
            ));
        }
    }

    // SSHD009: X11Forwarding yes
    if let Some(d) = find_global("x11forwarding") {
        if yes(&d.args) {
            findings.push(f(
                "SSHD009",
                Severity::Low,
                d.line,
                &d.raw,
                "X11 forwarding increases attack surface: a compromised client's X server can be reached and abused (X11 has weak isolation between clients).",
                "Set 'X11Forwarding no' unless remote GUI access is a hard requirement.",
            ));
        }
    }

    // SSHD010: AllowTcpForwarding where inappropriate (default is yes, flag if explicitly yes or unset)
    if let Some(d) = find_global("allowtcpforwarding") {
        if yes(&d.args) {
            findings.push(f(
                "SSHD010",
                Severity::Low,
                d.line,
                &d.raw,
                "TCP forwarding lets any authenticated user pivot the server into an arbitrary SOCKS/port proxy, bypassing network firewalls.",
                "Set 'AllowTcpForwarding no' (or 'local' if only local forwarding is needed) unless port forwarding is a required use case.",
            ));
        }
    }

    // SSHD011: missing MaxAuthTries (or too high)
    match find_global("maxauthtries") {
        None => findings.push(f(
            "SSHD011",
            Severity::Low,
            0,
            "(MaxAuthTries not set)",
            "OpenSSH's default of 6 permits many authentication attempts per connection, making online brute-force attacks cheaper.",
            "Add 'MaxAuthTries 3' to cut off brute-force attempts earlier.",
        )),
        Some(d) => {
            if let Ok(n) = d.args.trim().parse::<u32>() {
                if n > 4 {
                    findings.push(f(
                        "SSHD011",
                        Severity::Low,
                        d.line,
                        &d.raw,
                        "A high MaxAuthTries permits many authentication attempts per connection, making online brute-force attacks cheaper.",
                        "Lower MaxAuthTries to 3 or 4.",
                    ));
                }
            }
        }
    }

    // SSHD012: PermitUserEnvironment yes
    if let Some(d) = find_global("permituserenvironment") {
        if yes(&d.args) {
            findings.push(f(
                "SSHD012",
                Severity::Medium,
                d.line,
                &d.raw,
                "Users can set arbitrary environment variables (e.g. LD_PRELOAD) for their sessions via ~/.ssh/environment, which can be abused for privilege escalation or bypassing restricted commands.",
                "Set 'PermitUserEnvironment no'.",
            ));
        }
    }

    // SSHD013: UsePAM no
    if let Some(d) = find_global("usepam") {
        if d.args.trim().eq_ignore_ascii_case("no") {
            findings.push(f(
                "SSHD013",
                Severity::Medium,
                d.line,
                &d.raw,
                "Disabling PAM skips account/session controls such as password expiry, lockouts and centrally-managed access restrictions.",
                "Set 'UsePAM yes' unless you have a specific, understood reason not to.",
            ));
        }
    }

    // SSHD014: missing ClientAliveInterval
    if find_global("clientaliveinterval").is_none() {
        findings.push(f(
            "SSHD014",
            Severity::Info,
            0,
            "(ClientAliveInterval not set)",
            "Idle sessions (e.g. abandoned on a shared or stolen device) stay authenticated indefinitely instead of being dropped.",
            "Add 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' to drop unresponsive sessions.",
        ));
    }

    findings.sort();
    Ok(findings)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn ids(findings: &[Finding]) -> Vec<String> {
        findings.iter().map(|f| f.rule_id.clone()).collect()
    }

    fn has(findings: &[Finding], id: &str) -> bool {
        findings.iter().any(|f| f.rule_id == id)
    }

    #[test]
    fn permit_root_login_yes_flagged() {
        let f = audit("sshd_config", "PermitRootLogin yes\n").unwrap();
        assert!(has(&f, "SSHD001"));
        assert_eq!(
            f.iter().find(|x| x.rule_id == "SSHD001").unwrap().severity,
            Severity::Critical
        );
    }

    #[test]
    fn permit_root_login_no_clean() {
        let f = audit("sshd_config", "PermitRootLogin no\n").unwrap();
        assert!(!has(&f, "SSHD001"));
        assert!(!has(&f, "SSHD002"));
    }

    #[test]
    fn permit_root_login_without_password_flagged() {
        let f = audit("sshd_config", "PermitRootLogin without-password\n").unwrap();
        assert!(has(&f, "SSHD002"));
    }

    #[test]
    fn permit_root_login_prohibit_password_flagged() {
        let f = audit("sshd_config", "PermitRootLogin prohibit-password\n").unwrap();
        assert!(has(&f, "SSHD002"));
    }

    #[test]
    fn permit_root_login_unset_is_medium_default() {
        let f = audit("sshd_config", "Port 22\n").unwrap();
        let finding = f
            .iter()
            .find(|x| x.rule_id == "SSHD001")
            .expect("finding present");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.line, 0);
    }

    #[test]
    fn password_authentication_yes_flagged() {
        let f = audit("sshd_config", "PasswordAuthentication yes\n").unwrap();
        assert!(has(&f, "SSHD003"));
    }

    #[test]
    fn password_authentication_no_clean() {
        let f = audit("sshd_config", "PasswordAuthentication no\n").unwrap();
        assert!(!has(&f, "SSHD003"));
    }

    #[test]
    fn permit_empty_passwords_yes_flagged() {
        let f = audit("sshd_config", "PermitEmptyPasswords yes\n").unwrap();
        assert!(has(&f, "SSHD004"));
        assert_eq!(
            f.iter().find(|x| x.rule_id == "SSHD004").unwrap().severity,
            Severity::Critical
        );
    }

    #[test]
    fn permit_empty_passwords_no_clean() {
        let f = audit("sshd_config", "PermitEmptyPasswords no\n").unwrap();
        assert!(!has(&f, "SSHD004"));
    }

    #[test]
    fn protocol_1_flagged() {
        let f = audit("sshd_config", "Protocol 1\n").unwrap();
        assert!(has(&f, "SSHD005"));
    }

    #[test]
    fn protocol_2_1_flagged() {
        let f = audit("sshd_config", "Protocol 2,1\n").unwrap();
        assert!(has(&f, "SSHD005"));
    }

    #[test]
    fn protocol_2_clean() {
        let f = audit("sshd_config", "Protocol 2\n").unwrap();
        assert!(!has(&f, "SSHD005"));
    }

    #[test]
    fn weak_ciphers_flagged() {
        let f = audit("sshd_config", "Ciphers aes256-gcm@openssh.com,3des-cbc\n").unwrap();
        assert!(has(&f, "SSHD006"));
    }

    #[test]
    fn strong_ciphers_clean() {
        let f = audit(
            "sshd_config",
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n",
        )
        .unwrap();
        assert!(!has(&f, "SSHD006"));
    }

    #[test]
    fn weak_macs_flagged() {
        let f = audit("sshd_config", "MACs hmac-md5,hmac-sha2-256\n").unwrap();
        assert!(has(&f, "SSHD007"));
    }

    #[test]
    fn strong_macs_clean() {
        let f = audit("sshd_config", "MACs hmac-sha2-512-etm@openssh.com\n").unwrap();
        assert!(!has(&f, "SSHD007"));
    }

    #[test]
    fn weak_kex_flagged() {
        let f = audit("sshd_config", "KexAlgorithms diffie-hellman-group1-sha1\n").unwrap();
        assert!(has(&f, "SSHD008"));
    }

    #[test]
    fn strong_kex_clean() {
        let f = audit("sshd_config", "KexAlgorithms curve25519-sha256\n").unwrap();
        assert!(!has(&f, "SSHD008"));
    }

    #[test]
    fn x11_forwarding_yes_flagged() {
        let f = audit("sshd_config", "X11Forwarding yes\n").unwrap();
        assert!(has(&f, "SSHD009"));
    }

    #[test]
    fn x11_forwarding_no_clean() {
        let f = audit("sshd_config", "X11Forwarding no\n").unwrap();
        assert!(!has(&f, "SSHD009"));
    }

    #[test]
    fn allow_tcp_forwarding_yes_flagged() {
        let f = audit("sshd_config", "AllowTcpForwarding yes\n").unwrap();
        assert!(has(&f, "SSHD010"));
    }

    #[test]
    fn allow_tcp_forwarding_no_clean() {
        let f = audit("sshd_config", "AllowTcpForwarding no\n").unwrap();
        assert!(!has(&f, "SSHD010"));
    }

    #[test]
    fn max_auth_tries_missing_flagged() {
        let f = audit("sshd_config", "Port 22\n").unwrap();
        assert!(has(&f, "SSHD011"));
    }

    #[test]
    fn max_auth_tries_high_flagged() {
        let f = audit("sshd_config", "MaxAuthTries 10\n").unwrap();
        assert!(has(&f, "SSHD011"));
    }

    #[test]
    fn max_auth_tries_low_clean() {
        let f = audit("sshd_config", "MaxAuthTries 3\n").unwrap();
        assert!(!has(&f, "SSHD011"));
    }

    #[test]
    fn permit_user_environment_yes_flagged() {
        let f = audit("sshd_config", "PermitUserEnvironment yes\n").unwrap();
        assert!(has(&f, "SSHD012"));
    }

    #[test]
    fn permit_user_environment_no_clean() {
        let f = audit("sshd_config", "PermitUserEnvironment no\n").unwrap();
        assert!(!has(&f, "SSHD012"));
    }

    #[test]
    fn use_pam_no_flagged() {
        let f = audit("sshd_config", "UsePAM no\n").unwrap();
        assert!(has(&f, "SSHD013"));
    }

    #[test]
    fn use_pam_yes_clean() {
        let f = audit("sshd_config", "UsePAM yes\n").unwrap();
        assert!(!has(&f, "SSHD013"));
    }

    #[test]
    fn client_alive_interval_missing_flagged() {
        let f = audit("sshd_config", "Port 22\n").unwrap();
        assert!(has(&f, "SSHD014"));
    }

    #[test]
    fn client_alive_interval_set_clean() {
        let f = audit("sshd_config", "ClientAliveInterval 300\n").unwrap();
        assert!(!has(&f, "SSHD014"));
    }

    #[test]
    fn match_block_directive_not_reported_globally() {
        // The hard case: PasswordAuthentication yes only inside a Match
        // block must not be reported as a global PasswordAuthentication
        // setting.
        let cfg = "PasswordAuthentication no\nMatch User deploy\n\tPasswordAuthentication yes\n";
        let f = audit("sshd_config", cfg).unwrap();
        assert!(
            !has(&f, "SSHD003"),
            "Match-scoped directive leaked into global check: {:?}",
            ids(&f)
        );
    }

    #[test]
    fn match_block_permit_root_login_not_global() {
        let cfg = "PermitRootLogin no\nMatch Address 10.0.0.0/8\n    PermitRootLogin yes\n";
        let f = audit("sshd_config", cfg).unwrap();
        assert!(!has(&f, "SSHD001"));
        assert!(!has(&f, "SSHD002"));
    }

    #[test]
    fn case_insensitive_keyword_and_yes() {
        let f = audit("sshd_config", "permitrootlogin YES\n").unwrap();
        assert!(has(&f, "SSHD001"));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let cfg = "# comment\n\n   \nPermitRootLogin no # trailing comment\n";
        let f = audit("sshd_config", cfg).unwrap();
        assert!(!has(&f, "SSHD001"));
        assert!(!has(&f, "SSHD002"));
    }

    #[test]
    fn line_number_accuracy() {
        let cfg = "Port 22\nProtocol 1\n";
        let f = audit("sshd_config", cfg).unwrap();
        let finding = f.iter().find(|x| x.rule_id == "SSHD005").expect("present");
        assert_eq!(finding.line, 2);
    }

    #[test]
    fn unterminated_quote_errors_cleanly() {
        let cfg = "Banner \"unterminated\n";
        let result = audit("sshd_config", cfg);
        assert!(result.is_err());
    }

    #[test]
    fn empty_file_no_panic() {
        let f = audit("sshd_config", "").unwrap();
        // Missing-directive info findings still fire on an empty file.
        assert!(has(&f, "SSHD014"));
    }

    #[test]
    fn findings_sorted_by_severity_desc() {
        let cfg = "PermitEmptyPasswords yes\nX11Forwarding yes\n";
        let f = audit("sshd_config", cfg).unwrap();
        for pair in f.windows(2) {
            assert!(pair[0].severity >= pair[1].severity);
        }
    }
}

//! Parser and rule set for nginx configuration files.
//!
//! nginx configs are a nested block language (`http { server { location /x
//! { ... } } }`). Two things a naive line-scanner gets wrong:
//!
//! 1. **Directive inheritance**: a directive set at `http` level (e.g.
//!    `add_header X-Frame-Options DENY`) applies to every `server`/`location`
//!    beneath it unless overridden. Reporting it "missing" on a child that
//!    never restates it is a false positive.
//! 2. **Block scope**: a directive inside an `if {}` block only fires
//!    conditionally, and `if` in a `location` block is notoriously easy to
//!    misuse for anything beyond `return`/`rewrite`/`break`/`set`.
//!
//! This module builds a real tree (not a flat token stream) so rules can
//! walk it with an accumulated "inherited context".

use crate::finding::{Finding, Severity, SourceKind};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct Directive {
    pub keyword: String,
    pub args: String,
    pub line: usize,
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct Block {
    /// Lower-cased block name, e.g. "http", "server", "location", "if".
    pub name: String,
    pub args: String,
    pub line: usize,
    pub children: Vec<Item>,
}

#[derive(Debug, Clone)]
pub enum Item {
    Directive(Directive),
    Block(Block),
}

#[derive(Debug, Clone)]
enum Tok {
    Word(String, usize),
    Semi(usize),
    LBrace(usize),
    RBrace(usize),
}

fn tokenize(content: &str) -> Result<Vec<Tok>, String> {
    let mut tokens = Vec::new();
    let mut chars = content.char_indices().peekable();
    let mut line = 1usize;
    let mut buf = String::new();
    let mut word_start_line = 1usize;

    macro_rules! flush {
        () => {
            if !buf.is_empty() {
                tokens.push(Tok::Word(std::mem::take(&mut buf), word_start_line));
            }
        };
    }

    while let Some((_, c)) = chars.next() {
        match c {
            '\n' => {
                flush!();
                line += 1;
            }
            '#' => {
                flush!();
                for (_, nc) in chars.by_ref() {
                    if nc == '\n' {
                        line += 1;
                        break;
                    }
                }
            }
            '"' | '\'' => {
                if buf.is_empty() {
                    word_start_line = line;
                }
                let quote = c;
                let mut closed = false;
                for (_, nc) in chars.by_ref() {
                    if nc == '\n' {
                        line += 1;
                    }
                    if nc == quote {
                        closed = true;
                        break;
                    }
                    buf.push(nc);
                }
                if !closed {
                    return Err(format!(
                        "line {word_start_line}: unterminated quoted string"
                    ));
                }
            }
            c if c.is_whitespace() => {
                flush!();
            }
            ';' => {
                flush!();
                tokens.push(Tok::Semi(line));
            }
            '{' => {
                flush!();
                tokens.push(Tok::LBrace(line));
            }
            '}' => {
                flush!();
                tokens.push(Tok::RBrace(line));
            }
            other => {
                if buf.is_empty() {
                    word_start_line = line;
                }
                buf.push(other);
            }
        }
    }
    flush!();
    Ok(tokens)
}

fn parse_level(tokens: &[Tok], pos: &mut usize, top_level: bool) -> Result<Vec<Item>, String> {
    let mut items = Vec::new();
    loop {
        match tokens.get(*pos) {
            None => {
                if top_level {
                    return Ok(items);
                }
                return Err("unexpected end of file: unterminated block, missing '}'".to_string());
            }
            Some(Tok::RBrace(l)) => {
                if top_level {
                    return Err(format!("line {l}: unexpected '}}' with no matching '{{'"));
                }
                *pos += 1;
                return Ok(items);
            }
            Some(Tok::Semi(l)) => {
                return Err(format!("line {l}: unexpected ';' with no directive"));
            }
            Some(Tok::LBrace(l)) => {
                return Err(format!("line {l}: unexpected '{{' with no block name"));
            }
            Some(Tok::Word(_, start_line)) => {
                let start_line = *start_line;
                let mut words = Vec::new();
                let is_directive = loop {
                    match tokens.get(*pos) {
                        Some(Tok::Word(w, _)) => {
                            words.push(w.clone());
                            *pos += 1;
                        }
                        Some(Tok::Semi(_)) => {
                            *pos += 1;
                            break true;
                        }
                        Some(Tok::LBrace(_)) => {
                            *pos += 1;
                            break false;
                        }
                        Some(Tok::RBrace(l)) => {
                            return Err(format!("line {l}: unexpected '}}' before ';' or '{{'"));
                        }
                        None => {
                            return Err(format!(
                                "line {start_line}: unexpected end of file, expected ';' or '{{'"
                            ));
                        }
                    }
                };
                if words.is_empty() {
                    return Err(format!("line {start_line}: empty statement"));
                }
                let raw = words.join(" ");
                if is_directive {
                    items.push(Item::Directive(Directive {
                        keyword: words[0].to_ascii_lowercase(),
                        args: words[1..].join(" "),
                        line: start_line,
                        raw,
                    }));
                } else {
                    let children = parse_level(tokens, pos, false)?;
                    items.push(Item::Block(Block {
                        name: words[0].to_ascii_lowercase(),
                        args: words[1..].join(" "),
                        line: start_line,
                        children,
                    }));
                }
            }
        }
    }
}

/// Parse nginx config `content` into a tree of directives and blocks.
///
/// # Errors
/// Returns an error for malformed input: unterminated quotes, a `;` or `{`
/// with no preceding directive/block name, or an unbalanced `{`/`}`.
pub fn parse(content: &str) -> Result<Vec<Item>, String> {
    let tokens = tokenize(content)?;
    let mut pos = 0;
    let items = parse_level(&tokens, &mut pos, true)?;
    debug_assert_eq!(pos, tokens.len());
    Ok(items)
}

/// Directives inherited from ancestor blocks, accumulated as we descend.
#[derive(Debug, Clone, Default)]
struct Ctx {
    headers: BTreeSet<String>,
    proxy_host_set: bool,
}

const REQUIRED_HEADERS: &[(&str, &str)] = &[
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
];

const WEAK_SSL_PROTOCOLS: &[&str] = &["tlsv1", "tlsv1.1", "sslv2", "sslv3"];
const WEAK_CIPHER_TOKENS: &[&str] = &["rc4", "md5", "3des", "null", "export", "des-cbc3"];

fn own_directives(block: &Block) -> impl Iterator<Item = &Directive> {
    block.children.iter().filter_map(|i| match i {
        Item::Directive(d) => Some(d),
        Item::Block(_) => None,
    })
}

fn find_own<'a>(block: &'a Block, keyword: &str) -> Option<&'a Directive> {
    own_directives(block).find(|d| d.keyword == keyword)
}

fn header_name_of(args: &str) -> Option<String> {
    args.split_whitespace().next().map(str::to_ascii_lowercase)
}

fn is_tls_server(server: &Block) -> bool {
    if own_directives(server).any(|d| d.keyword == "ssl_certificate") {
        return true;
    }
    own_directives(server)
        .any(|d| d.keyword == "listen" && d.args.to_ascii_lowercase().contains("ssl"))
}

fn has_https_redirect(items: &[Item]) -> bool {
    for item in items {
        match item {
            Item::Directive(d) if d.keyword == "return" => {
                let a = d.args.to_ascii_lowercase();
                if (a.contains("301") || a.contains("302")) && a.contains("https") {
                    return true;
                }
            }
            Item::Directive(d) if d.keyword == "rewrite" => {
                let a = d.args.to_ascii_lowercase();
                if a.contains("https") {
                    return true;
                }
            }
            Item::Block(b) => {
                if has_https_redirect(&b.children) {
                    return true;
                }
            }
            Item::Directive(_) => {}
        }
    }
    false
}

/// Parse and audit `content`, returning every rule violation found.
///
/// # Errors
/// Returns an error if `content` cannot be parsed (see [`parse`]).
#[allow(clippy::too_many_lines)]
pub fn audit(file: &str, content: &str) -> Result<Vec<Finding>, String> {
    let tree = parse(content)?;
    let mut findings = Vec::new();
    walk(file, &tree, &Ctx::default(), &mut findings);
    findings.sort();
    Ok(findings)
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
        SourceKind::Nginx,
        file,
        line,
        evidence,
        consequence,
        fix,
    )
}

fn walk(file: &str, items: &[Item], ctx: &Ctx, findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive(d) => check_directive(file, d, findings),
            Item::Block(b) => check_block(file, b, ctx.clone(), findings),
        }
    }
}

fn check_directive(file: &str, d: &Directive, findings: &mut Vec<Finding>) {
    if d.keyword == "autoindex" && d.args.trim().eq_ignore_ascii_case("on") {
        findings.push(mk(
            "NGX001",
            Severity::High,
            file,
            d.line,
            &d.raw,
            "Directory listing is enabled: any request to a directory without an index file returns a full file listing, exposing filenames (backups, source, credentials) an attacker would otherwise have to guess.",
            "Remove the directive or set 'autoindex off;'.",
        ));
    }
    if d.keyword == "server_tokens" && d.args.trim().eq_ignore_ascii_case("on") {
        findings.push(mk(
            "NGX002",
            Severity::Low,
            file,
            d.line,
            &d.raw,
            "The nginx version number is disclosed in the Server header and default error pages, helping an attacker match known CVEs to your exact build.",
            "Set 'server_tokens off;'.",
        ));
    }
    if d.keyword == "client_max_body_size" && d.args.trim() == "0" {
        findings.push(mk(
            "NGX009",
            Severity::Medium,
            file,
            d.line,
            &d.raw,
            "Request body size is unbounded, letting a client stream an arbitrarily large upload and exhaust disk, memory or bandwidth (a low-effort denial of service).",
            "Set an explicit upper bound, e.g. 'client_max_body_size 10m;'.",
        ));
    }
}

#[allow(clippy::too_many_lines)]
fn check_block(file: &str, block: &Block, mut ctx: Ctx, findings: &mut Vec<Finding>) {
    for d in own_directives(block) {
        // Note: check_directive() is deliberately not called here — walk()
        // calls it once for every directive (including these) when it
        // recurses into block.children below. Calling it here too would
        // double-report autoindex/server_tokens/client_max_body_size.
        if d.keyword == "add_header" {
            if let Some(name) = header_name_of(&d.args) {
                ctx.headers.insert(name);
            }
        }
        if d.keyword == "proxy_set_header"
            && d.args
                .split_whitespace()
                .next()
                .is_some_and(|h| h.eq_ignore_ascii_case("host"))
        {
            ctx.proxy_host_set = true;
        }
        if d.keyword == "ssl_protocols" {
            let weak: Vec<&str> = d
                .args
                .split_whitespace()
                .filter(|p| WEAK_SSL_PROTOCOLS.contains(&p.to_ascii_lowercase().as_str()))
                .collect();
            if !weak.is_empty() {
                findings.push(mk(
                    "NGX004",
                    Severity::High,
                    file,
                    d.line,
                    &d.raw,
                    "TLSv1/TLSv1.1/SSLv2/SSLv3 have known cryptographic weaknesses (POODLE, BEAST, weak ciphers) and allow protocol-downgrade attacks against clients.",
                    "Set 'ssl_protocols TLSv1.2 TLSv1.3;'.",
                ));
            }
        }
        if d.keyword == "ssl_ciphers" {
            let lower = d.args.to_ascii_lowercase();
            let weak: Vec<&str> = WEAK_CIPHER_TOKENS
                .iter()
                .copied()
                .filter(|t| lower.contains(t))
                .collect();
            if !weak.is_empty() {
                findings.push(mk(
                    "NGX005",
                    Severity::High,
                    file,
                    d.line,
                    &d.raw,
                    &format!(
                        "Weak cipher token(s) allowed ({}); these are vulnerable to known plaintext-recovery or downgrade attacks.",
                        weak.join(", ")
                    ),
                    "Use a modern cipher suite, e.g. 'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;' with 'ssl_prefer_server_ciphers off;'.",
                ));
            }
        }
    }

    if block.name == "if" {
        for item in &block.children {
            if let Item::Directive(d) = item {
                if !matches!(d.keyword.as_str(), "return" | "rewrite" | "break" | "set") {
                    findings.push(mk(
                        "NGX011",
                        Severity::Medium,
                        file,
                        block.line,
                        &format!("if ({}) {{ {} ... }}", block.args, d.keyword),
                        "nginx 'if' in a location context only reliably supports return/rewrite/break/set. Any other directive inside it (proxy_pass, add_header, etc.) can behave unpredictably, which has previously been used to bypass intended access or header controls.",
                        "Move the logic out of 'if' using nginx's built-in variables/maps, or restrict the if body to return/rewrite.",
                    ));
                    break;
                }
            }
        }
    }

    if block.name == "location" {
        if let Some(alias) = find_own(block, "alias") {
            let loc_path = block.args.trim();
            let alias_val = alias.args.trim();
            if !loc_path.ends_with('/') && !alias_val.ends_with('/') && !loc_path.contains('~') {
                findings.push(mk(
                    "NGX012",
                    Severity::High,
                    file,
                    alias.line,
                    &alias.raw,
                    "Without a trailing slash on both the location prefix and the alias target, nginx's prefix matching lets a crafted path (e.g. appending '../') escape the intended directory and read files elsewhere on disk.",
                    &format!("Add a trailing slash to both, e.g. 'location {loc_path}/ {{ alias {alias_val}/; }}'."),
                ));
            }
        }
        if let Some(pp) = find_own(block, "proxy_pass").filter(|_| !ctx.proxy_host_set) {
            findings.push(mk(
                "NGX010",
                Severity::Medium,
                file,
                pp.line,
                &pp.raw,
                "Without forwarding the original Host header, the backend sees nginx's upstream address instead of the real request host, which can break host-based routing, generate wrong absolute URLs, or bypass backend virtual-host security checks.",
                "Add 'proxy_set_header Host $host;' in this location (or an ancestor server/http block).",
            ));
        }
    }

    if block.name == "server" {
        let label = server_label(block);
        let tls = is_tls_server(block);
        if !tls {
            let redirects = has_https_redirect(&block.children);
            if !redirects {
                findings.push(mk(
                    "NGX003",
                    Severity::Medium,
                    file,
                    block.line,
                    &label,
                    "Plaintext HTTP is served with no redirect to HTTPS, so credentials and session cookies can be sent or intercepted in cleartext by any on-path attacker.",
                    "Add 'return 301 https://$host$request_uri;' in this server block (or terminate TLS here).",
                ));
            }
        }

        let mut have: BTreeSet<String> = ctx.headers.clone();
        collect_headers(&block.children, &mut have);
        for (key, display) in REQUIRED_HEADERS {
            if !have.contains(*key) {
                findings.push(mk(
                    if *key == "x-content-type-options" {
                        "NGX006"
                    } else {
                        "NGX007"
                    },
                    Severity::Low,
                    file,
                    block.line,
                    &label,
                    &missing_header_consequence(key),
                    &format!(
                        "Add 'add_header {display} {};' (at http, server, or this location level).",
                        default_header_value(key)
                    ),
                ));
            }
        }
        if tls && !have.contains("strict-transport-security") {
            findings.push(mk(
                "NGX008",
                Severity::Low,
                file,
                block.line,
                &label,
                "Without HSTS, a browser will happily fall back to plaintext HTTP on this host, leaving a window for SSL-stripping attacks even though TLS is available.",
                "Add 'add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;'.",
            ));
        }
    }

    walk(file, &block.children, &ctx, findings);
}

fn server_label(block: &Block) -> String {
    if block.args.trim().is_empty() {
        "server".to_string()
    } else {
        format!("server {}", block.args)
    }
}

fn collect_headers(items: &[Item], out: &mut BTreeSet<String>) {
    for item in items {
        match item {
            Item::Directive(d) if d.keyword == "add_header" => {
                if let Some(name) = header_name_of(&d.args) {
                    out.insert(name);
                }
            }
            Item::Block(b) => collect_headers(&b.children, out),
            Item::Directive(_) => {}
        }
    }
}

fn missing_header_consequence(key: &str) -> String {
    match key {
        "x-content-type-options" => {
            "Without 'nosniff', browsers may MIME-sniff a response into an executable context (e.g. treating an uploaded file as HTML/JS), enabling stored XSS from user-supplied content.".to_string()
        }
        _ => "Without this header, the response can be framed by another site, enabling clickjacking attacks that trick users into acting on this site unknowingly.".to_string(),
    }
}

fn default_header_value(key: &str) -> &'static str {
    match key {
        "x-content-type-options" => "nosniff",
        _ => "DENY",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn has(findings: &[Finding], id: &str) -> bool {
        findings.iter().any(|f| f.rule_id == id)
    }

    const TLS_SERVER: &str = r#"
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/cert.pem;
    ssl_certificate_key /etc/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header Strict-Transport-Security "max-age=63072000" always;
    server_name example.com;
}
"#;

    #[test]
    fn autoindex_on_flagged() {
        let f = audit("nginx.conf", "server { location / { autoindex on; } }").unwrap();
        assert!(has(&f, "NGX001"));
    }

    #[test]
    fn autoindex_off_clean() {
        let f = audit("nginx.conf", "server { location / { autoindex off; } }").unwrap();
        assert!(!has(&f, "NGX001"));
    }

    #[test]
    fn server_tokens_on_flagged() {
        let f = audit("nginx.conf", "http { server_tokens on; }").unwrap();
        assert!(has(&f, "NGX002"));
    }

    #[test]
    fn server_tokens_off_clean() {
        let f = audit("nginx.conf", "http { server_tokens off; }").unwrap();
        assert!(!has(&f, "NGX002"));
    }

    #[test]
    fn missing_https_redirect_flagged() {
        let f = audit("nginx.conf", "server { listen 80; server_name x.com; }").unwrap();
        assert!(has(&f, "NGX003"));
    }

    #[test]
    fn https_redirect_present_clean() {
        let f = audit(
            "nginx.conf",
            "server { listen 80; return 301 https://$host$request_uri; }",
        )
        .unwrap();
        assert!(!has(&f, "NGX003"));
    }

    #[test]
    fn tls_server_no_redirect_needed() {
        let f = audit("nginx.conf", TLS_SERVER).unwrap();
        assert!(!has(&f, "NGX003"));
    }

    #[test]
    fn weak_ssl_protocol_flagged() {
        let f = audit("nginx.conf", "server { ssl_protocols TLSv1 TLSv1.1; }").unwrap();
        assert!(has(&f, "NGX004"));
    }

    #[test]
    fn strong_ssl_protocol_clean() {
        let f = audit("nginx.conf", "server { ssl_protocols TLSv1.2 TLSv1.3; }").unwrap();
        assert!(!has(&f, "NGX004"));
    }

    #[test]
    fn weak_ssl_ciphers_flagged() {
        let f = audit("nginx.conf", "server { ssl_ciphers RC4-SHA:MD5; }").unwrap();
        assert!(has(&f, "NGX005"));
    }

    #[test]
    fn strong_ssl_ciphers_clean() {
        let f = audit(
            "nginx.conf",
            "server { ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256; }",
        )
        .unwrap();
        assert!(!has(&f, "NGX005"));
    }

    #[test]
    fn missing_content_type_options_flagged() {
        let f = audit("nginx.conf", "server { server_name x.com; }").unwrap();
        assert!(has(&f, "NGX006"));
    }

    #[test]
    fn missing_frame_options_flagged() {
        let f = audit("nginx.conf", "server { server_name x.com; }").unwrap();
        assert!(has(&f, "NGX007"));
    }

    #[test]
    fn headers_present_on_server_clean() {
        let cfg = r"server {
            add_header X-Content-Type-Options nosniff;
            add_header X-Frame-Options DENY;
        }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(!has(&f, "NGX006"));
        assert!(!has(&f, "NGX007"));
    }

    #[test]
    fn headers_inherited_from_http_not_double_flagged() {
        // The hard case: a header set once at http level applies to every
        // server beneath it and must not be reported missing per-server.
        let cfg = r"http {
            add_header X-Content-Type-Options nosniff;
            add_header X-Frame-Options DENY;
            server {
                server_name a.com;
            }
            server {
                server_name b.com;
            }
        }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(!has(&f, "NGX006"));
        assert!(!has(&f, "NGX007"));
    }

    #[test]
    fn header_missing_on_one_of_two_servers() {
        let cfg = r"http {
            server {
                server_name a.com;
                add_header X-Content-Type-Options nosniff;
                add_header X-Frame-Options DENY;
            }
            server {
                server_name b.com;
            }
        }";
        let f = audit("nginx.conf", cfg).unwrap();
        let missing_count = f.iter().filter(|x| x.rule_id == "NGX006").count();
        assert_eq!(missing_count, 1);
    }

    #[test]
    fn missing_hsts_on_tls_server_flagged() {
        let cfg = r"server {
            listen 443 ssl;
            ssl_certificate /etc/ssl/cert.pem;
            add_header X-Content-Type-Options nosniff;
            add_header X-Frame-Options DENY;
        }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(has(&f, "NGX008"));
    }

    #[test]
    fn hsts_present_on_tls_server_clean() {
        let f = audit("nginx.conf", TLS_SERVER).unwrap();
        assert!(!has(&f, "NGX008"));
    }

    #[test]
    fn hsts_not_required_on_plain_http_server() {
        let cfg = "server { listen 80; return 301 https://$host$request_uri; }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(!has(&f, "NGX008"));
    }

    #[test]
    fn client_max_body_size_zero_flagged() {
        let f = audit("nginx.conf", "http { client_max_body_size 0; }").unwrap();
        assert!(has(&f, "NGX009"));
    }

    #[test]
    fn client_max_body_size_bounded_clean() {
        let f = audit("nginx.conf", "http { client_max_body_size 10m; }").unwrap();
        assert!(!has(&f, "NGX009"));
    }

    #[test]
    fn proxy_pass_without_host_header_flagged() {
        let cfg = "server { location / { proxy_pass http://backend; } }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(has(&f, "NGX010"));
    }

    #[test]
    fn proxy_pass_with_host_header_clean() {
        let cfg = r"server {
            location / {
                proxy_set_header Host $host;
                proxy_pass http://backend;
            }
        }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(!has(&f, "NGX010"));
    }

    #[test]
    fn proxy_pass_host_header_inherited_from_server_clean() {
        let cfg = r"server {
            proxy_set_header Host $host;
            location / {
                proxy_pass http://backend;
            }
        }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(!has(&f, "NGX010"));
    }

    #[test]
    fn if_with_proxy_pass_flagged() {
        let cfg = r"server {
            location / {
                if ($request_method = POST) {
                    proxy_pass http://backend;
                }
            }
        }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(has(&f, "NGX011"));
    }

    #[test]
    fn if_with_only_return_clean() {
        let cfg = r"server {
            location / {
                if ($request_method = POST) {
                    return 405;
                }
            }
        }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(!has(&f, "NGX011"));
    }

    #[test]
    fn alias_without_trailing_slash_flagged() {
        let cfg = "server { location /files { alias /data/files; } }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(has(&f, "NGX012"));
    }

    #[test]
    fn alias_with_trailing_slash_clean() {
        let cfg = "server { location /files/ { alias /data/files/; } }";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(!has(&f, "NGX012"));
    }

    #[test]
    fn nested_http_server_location_parses() {
        let cfg = r"http {
            server {
                location / {
                    location /inner {
                        return 200;
                    }
                }
            }
        }";
        assert!(audit("nginx.conf", cfg).is_ok());
    }

    #[test]
    fn comments_are_ignored() {
        let cfg = "server {\n    # autoindex on;\n    autoindex off;\n}\n";
        let f = audit("nginx.conf", cfg).unwrap();
        assert!(!has(&f, "NGX001"));
    }

    #[test]
    fn quoted_string_with_braces_does_not_confuse_parser() {
        let cfg = r#"server { add_header X-Test "value with { and } chars"; }"#;
        assert!(audit("nginx.conf", cfg).is_ok());
    }

    #[test]
    fn unterminated_brace_errors_cleanly() {
        let cfg = "server { location / { autoindex on; }";
        let result = audit("nginx.conf", cfg);
        assert!(result.is_err());
    }

    #[test]
    fn stray_closing_brace_errors_cleanly() {
        let cfg = "server { } }";
        let result = audit("nginx.conf", cfg);
        assert!(result.is_err());
    }

    #[test]
    fn unterminated_quote_errors_cleanly() {
        let cfg = "server { add_header X-Test \"unterminated; }";
        let result = audit("nginx.conf", cfg);
        assert!(result.is_err());
    }

    #[test]
    fn line_number_accuracy_in_nested_block() {
        let cfg = "http {\n    server {\n        autoindex on;\n    }\n}\n";
        let f = audit("nginx.conf", cfg).unwrap();
        let finding = f.iter().find(|x| x.rule_id == "NGX001").expect("present");
        assert_eq!(finding.line, 3);
    }

    #[test]
    fn empty_file_parses_with_no_findings_of_block_rules() {
        let f = audit("nginx.conf", "").unwrap();
        assert!(!has(&f, "NGX001"));
        assert!(!has(&f, "NGX003"));
    }
}

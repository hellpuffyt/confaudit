# confaudit

Audit nginx, sshd, and Docker configuration files for settings that weaken
security — and for every finding, say exactly what an attacker gains or
what breaks.

## What

`confaudit` reads `sshd_config`, nginx configuration files, and
`Dockerfile`s from disk and checks them against a rule set built from
well-known configuration mistakes: `PermitRootLogin yes`, directory
listings left on, a Dockerfile that never drops root, TLS 1.0 still
accepted, and dozens more. It is a static analyzer for **security
posture**, not a syntax linter.

## Why

Server configs get copied from a blog post once and never revisited.
`PermitRootLogin yes` survives for years because nothing ever flags it.
An nginx `location` block silently serves directory listings. A
Dockerfile runs as root and bakes a secret into a layer that `docker
history` will happily show anyone with pull access. Syntax linters won't
catch any of this — they check that the file parses, not that it's safe.
`confaudit` checks the second thing, and every finding names the
consequence, which is what actually gets a misconfiguration fixed.

`confaudit` never makes a network request. It reads files on disk. If
you want to audit the HTTP response headers a live server actually
sends, that's a different (and complementary) kind of tool.

## Features

- Three real, hand-written parsers — not one big regex sweep:
  - `sshd_config`, with correct `Match`-block scoping (a directive inside
    a `Match` block is conditional and is never reported as a global
    setting).
  - nginx, with a full block tree and directive **inheritance**
    (`http` -> `server` -> `location`), so a header set once at `http`
    level is correctly recognized on every `server` beneath it.
  - `Dockerfile`, with backslash line-continuation joining and comment
    handling.
- 36 rules across the three formats (see the reference table below).
- Text, JSON, and [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
  output — SARIF uploads straight into GitHub code scanning.
- `--severity` threshold filtering and `--ignore` rule suppression.
- Non-zero exit status when findings meet or exceed the severity
  threshold, so it's usable as a CI gate.
- Malformed input (unterminated quotes, unbalanced braces, dangling line
  continuations) returns a clean error instead of panicking.

## Supported formats

| Format       | File detection                                              |
| ------------ | ------------------------------------------------------------ |
| `sshd_config`| filename `sshd_config` or `sshd_config.*`                    |
| nginx        | `*.conf`, or a filename containing `nginx`                   |
| Dockerfile   | filename `Dockerfile`, `Dockerfile.*`, or `*.dockerfile`     |

## Architecture

```
src/
  finding.rs        Finding/Severity/SourceKind — the shared result type
  parsers/
    sshd.rs          sshd_config tokenizer + Match-scope tracking + rules
    nginx.rs         nginx block-tree parser + inheritance-aware rules
    dockerfile.rs    Dockerfile instruction parser + rules
    mod.rs           file-kind detection
  output/
    text.rs, json.rs, sarif.rs
  lib.rs             ties parsing + filtering together for main.rs and tests
  main.rs            CLI (clap)
```

Each parser produces a small typed tree (or, for sshd, a flat list of
directives tagged with their `Match` scope) before any rule runs — rules
never regex the raw file text. This is what makes the two hard cases
(conditional `Match` directives, inherited nginx headers) tractable and
testable.

## Installation

```
git clone https://github.com/hellpuffyt/confaudit.git
cd confaudit
cargo install --path .
```

Or build a binary without installing it:

```
cargo build --release
./target/release/confaudit --help
```

## Usage

```
confaudit [OPTIONS] <PATH>...

Arguments:
  <PATH>...  Configuration file(s) to audit (sshd_config, nginx *.conf, Dockerfile)

Options:
  -f, --format <FORMAT>      Output format: text, json, or sarif [default: text]
      --severity <SEVERITY>  Only report findings at or above this severity:
                              info, low, medium, high, critical [default: info]
      --ignore <IDS>         Comma-separated rule IDs to suppress (e.g. SSHD001,NGX002)
      --no-fail               Exit 0 even if findings were reported
  -h, --help                  Print help
  -V, --version                Print version
```

Exit codes: `0` no findings at/above threshold, `1` findings reported,
`2` a file could not be read/parsed/audited.

## Rules reference

### sshd_config

| Rule ID | Severity | Trigger | Consequence |
| ------- | -------- | ------- | ----------- |
| SSHD001 | Critical / Medium | `PermitRootLogin yes`, or unset | Direct root login skips privilege escalation entirely |
| SSHD002 | High | `PermitRootLogin without-password`/`prohibit-password` | Root key login stays possible with no second factor |
| SSHD003 | High | `PasswordAuthentication yes` | Exposes the server to credential-stuffing/brute force |
| SSHD004 | Critical | `PermitEmptyPasswords yes` | Blank-password accounts need no credential at all |
| SSHD005 | Critical | `Protocol 1` present | SSHv1 is trivially MITM'd |
| SSHD006 | High | Weak `Ciphers` (CBC/RC4) | Vulnerable to plaintext-recovery attacks |
| SSHD007 | High | Weak `MACs` (MD5/SHA1-96) | Vulnerable to forgery/collision attacks |
| SSHD008 | High | Weak `KexAlgorithms` (SHA-1/small DH) | Weakens forward secrecy (Logjam-style) |
| SSHD009 | Low | `X11Forwarding yes` | Increases attack surface via X11's weak client isolation |
| SSHD010 | Low | `AllowTcpForwarding yes` | Lets any user pivot the server into an arbitrary proxy |
| SSHD011 | Low | Missing/high `MaxAuthTries` | Cheaper online brute-force attempts |
| SSHD012 | Medium | `PermitUserEnvironment yes` | Enables `LD_PRELOAD`-style privilege escalation |
| SSHD013 | Medium | `UsePAM no` | Skips account lockout/expiry controls |
| SSHD014 | Info | Missing `ClientAliveInterval` | Idle sessions never get dropped |

### nginx

| Rule ID | Severity | Trigger | Consequence |
| ------- | -------- | ------- | ----------- |
| NGX001 | High | `autoindex on` | Directory listing exposes filenames an attacker would otherwise guess |
| NGX002 | Low | `server_tokens on` | Discloses nginx version for CVE matching |
| NGX003 | Medium | Non-TLS `server` with no HTTPS redirect | Credentials/cookies can travel in cleartext |
| NGX004 | High | Weak `ssl_protocols` (TLSv1/1.1/SSLv2/SSLv3) | Known protocol weaknesses, downgrade attacks |
| NGX005 | High | Weak `ssl_ciphers` (RC4/MD5/3DES/NULL/EXPORT) | Plaintext-recovery/downgrade attacks |
| NGX006 | Low | Missing `X-Content-Type-Options` (inheritance-aware) | Enables MIME-sniffing-based stored XSS |
| NGX007 | Low | Missing `X-Frame-Options` (inheritance-aware) | Enables clickjacking |
| NGX008 | Low | Missing `Strict-Transport-Security` on a TLS server | Allows SSL-stripping fallback to HTTP |
| NGX009 | Medium | `client_max_body_size 0` | Unbounded upload size enables resource-exhaustion DoS |
| NGX010 | Medium | `proxy_pass` without `proxy_set_header Host` (inheritance-aware) | Breaks host-based routing / backend vhost checks |
| NGX011 | Medium | Non-`return`/`rewrite`/`break`/`set` directive inside `if` | nginx's `if` misbehaves outside that narrow set |
| NGX012 | High | `alias` without a trailing slash matching the `location` | Classic path-traversal footgun |

### Dockerfile

| Rule ID | Severity | Trigger | Consequence |
| ------- | -------- | ------- | ----------- |
| DOCK001 | High | No `USER`, or `USER root`/`0` | Compromise runs as container root |
| DOCK002 | Medium | `latest` tag or no tag | Build is not reproducible; base can silently change |
| DOCK003 | Medium | `ADD` from `http(s)://` | No integrity check on the fetched content |
| DOCK004 | Critical | Secret-shaped key in `ENV`/`ARG` with a value | Baked permanently into image layer history |
| DOCK005 | Low | `apt-get install` missing `--no-install-recommends` or cache cleanup | Bloats image and installed-package attack surface |
| DOCK006 | High | `curl`/`wget` piped into `sh`/`bash` | Arbitrary code execution from an unverified download |
| DOCK007 | High | `--privileged` referenced in a `RUN` | Disables container isolation for anything relying on it |
| DOCK008 | Info | No `HEALTHCHECK` | Orchestrators can't detect a hung process |
| DOCK009 | Low | `sudo` in a `RUN` | Redundant during build; risky if it reaches runtime |
| DOCK010 | Info | `COPY . .` before the dependency install step | Busts the layer cache on every source change |

## Examples

```
$ confaudit testdata/sshd/bad_sshd_config
[critical] SSHD001 (sshd) - testdata/sshd/bad_sshd_config:2
  found:      PermitRootLogin yes
  consequence: An attacker who obtains or brute-forces any valid credential (password or key) can log in directly as root, skipping privilege escalation entirely.
  fix:        Set 'PermitRootLogin no' and use sudo with a named account for administrative access.
...
Summary: 13 finding(s) - critical=2 high=6 medium=1 low=3 info=1
```

```
$ confaudit --format sarif testdata/nginx/bad.conf > results.sarif
```

```
$ confaudit --severity high --ignore DOCK008 testdata/docker/Dockerfile.bad
```

## Testing

```
cargo test --all-targets
```

The suite covers every rule in both directions (triggers and does-not-
trigger), plus:

- an sshd directive inside a `Match` block is never reported as a global
  setting;
- an nginx header inherited from `http` is never reported missing on a
  child `server`;
- line-number accuracy across flat, nested, and continuation-joined
  input;
- malformed input (unterminated quotes/strings, unbalanced braces,
  dangling backslash continuations) returns a clean `Err` instead of
  panicking;
- CLI-level tests against the fixtures in `testdata/` covering exit
  codes, `--ignore`, `--no-fail`, and all three output formats.

## Security

`confaudit` only reads files you point it at; it makes no network
requests and executes nothing from the files it audits. The fixtures in
`testdata/` use obviously fake secret values (e.g.
`fake-build-time-token-do-not-use`) — they exist to exercise the secret-
detection rule, not as real credentials.

## License

MIT — see [LICENSE](LICENSE).

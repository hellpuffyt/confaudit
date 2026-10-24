# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed

- nginx: `add_header` inheritance was modelled as a union. nginx drops
  *all* inherited `add_header` directives from a level that has any of
  its own, so a server with only an HSTS `add_header` sent neither
  `X-Frame-Options` nor `X-Content-Type-Options` while confaudit reported
  it clean (the bundled `good.conf` had exactly this bug and is fixed).
  Locations that drop inherited headers are now reported, and a header
  set in only one location no longer covers the whole server.
- nginx NGX012 flagged the harmless form (`location /x { alias /d/x; }`)
  and missed the exploitable off-by-slash form
  (`location /x { alias /d/x/; }`).
- nginx NGX012's suggested fix doubled the alias's trailing slash
  (`alias /var/www/static//;`); it now reads `alias /var/www/static/;`.
- sshd: `Keyword=value` syntax was not parsed (`PermitRootLogin=yes` was
  reported as "unset", medium instead of critical); `Ciphers`/`MACs`/
  `KexAlgorithms` lists starting with `-` (removing algorithms) were
  reported as enabling them.
- Dockerfile: DOCK001 used the last `USER` in any stage, so a `USER` in a
  builder stage hid a root final image; DOCK002 flagged `FROM <stage>`
  references and `--platform=` flags as untagged images, and skipped any
  image whose name contained "scratch".
- `cargo doc` failed under `-D warnings` (links to private items).
- README example summary did not match the tool's output.

### Added

- `testdata/corpus/` false-positive/false-negative fixtures pinned by
  `tests/cli.rs`; `SECURITY.md`, `.editorconfig`,
  `docs/PRODUCTION_READINESS.md`.

## [0.1.0] - 2026-08-30

### Added

- Initial release.
- `sshd_config` parser with `Match`-block scoping and 14 rules covering
  root login, password authentication, empty passwords, protocol version,
  weak ciphers/MACs/KexAlgorithms, X11 and TCP forwarding, brute-force
  limits, user environment injection, PAM, and idle session timeouts.
- nginx parser with full block-tree parsing, directive inheritance
  (`http` -> `server` -> `location`), and 12 rules covering directory
  listing, version disclosure, HTTPS redirection, weak TLS protocols and
  ciphers, missing security headers, unbounded request bodies, proxy Host
  forwarding, unsafe `if` usage, and `alias` traversal risk.
- Dockerfile parser with line-continuation handling and 10 rules covering
  root users, unpinned/`latest` base images, `ADD` from a URL, secrets in
  `ENV`/`ARG`, unclean `apt-get install`, `curl | sh`, `--privileged`
  hints, missing `HEALTHCHECK`, `sudo` usage, and cache-busting `COPY . .`.
- Text, JSON, and SARIF 2.1.0 output formats.
- `--severity` threshold filtering and `--ignore` rule suppression.
- Non-zero exit status when findings meet or exceed the severity threshold.

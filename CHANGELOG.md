# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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

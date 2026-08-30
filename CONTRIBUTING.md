# Contributing

## Development setup

```
git clone https://github.com/hellpuffyt/confaudit.git
cd confaudit
cargo build
```

## Before opening a pull request

Run the full gate locally:

```
cargo test --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

All three must pass. CI runs the same checks on Linux, Windows, and macOS,
plus a pinned MSRV build and a release smoke test.

## Adding a new rule

1. Pick the next free rule ID for the relevant parser (`SSHD###`,
   `NGX###`, or `DOCK###`). Never reuse or renumber an existing ID —
   downstream SARIF/JSON consumers may key on it.
2. Implement the check in the matching `src/parsers/*.rs` module.
3. Every rule needs a test in **both directions**: one fixture that
   triggers the finding, one that doesn't.
4. State the consequence in terms of what an attacker gains or what
   breaks — not just "this is insecure."
5. Update the rules reference table in `README.md`.
6. If the rule is easy to demonstrate, add or extend a fixture under
   `testdata/` — but never put a real secret in a fixture. Use obviously
   fake values (e.g. `hunter2fake`, `fake-build-time-token-do-not-use`).

## Reporting a security issue

This tool audits configuration files; it does not process untrusted
network input. If you find a case where confaudit panics on malformed
input instead of returning a clean error, please open an issue with the
input that triggers it.

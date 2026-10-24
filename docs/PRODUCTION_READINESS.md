# Production readiness — confaudit

Audit date: 2026-10-22. Branch: `audit/production-readiness`.
Tested commit: `4192d0e` (the final commit adds only this file).

## Scope

`confaudit` statically audits `sshd_config`, nginx configuration and
`Dockerfile`s with three hand-written parsers (`src/parsers/`) and 36
rules, emitting text, JSON or SARIF 2.1.0, with `--severity`, `--ignore`
and a CI exit code. No network access; it never executes anything from
the files it reads.

## Platforms and prerequisites

- Declared MSRV Rust 1.74 (CI job). Not run locally: the oldest toolchain
  on the audit host is 1.85. No newer-than-1.74 language features were
  introduced by this audit.
- Verified on macOS 27 (Apple M5). CI covers Linux, macOS, Windows.

## Clean-clone verification (literal README steps)

```
git clone -b audit/production-readiness <repo> confaudit && cd confaudit
cargo install --locked --path . --root <scratch>/inst   # exit 0
cargo build --release                                    # exit 0
cargo test --all-targets                                 # exit 0 — 154 passed (141 lib, 13 CLI), 0 failed, 0 ignored
cargo clippy --all-targets -- -D warnings                # exit 0
cargo fmt --all -- --check                               # exit 0
confaudit testdata/sshd/bad_sshd_config                  # exit 1; Summary: 13 finding(s) - critical=3 high=4 medium=2 low=3 info=1
confaudit --format sarif testdata/nginx/bad.conf > results.sarif   # exit 1; SARIF 2.1.0 with 14 results
confaudit --severity high --ignore DOCK008 testdata/docker/Dockerfile.bad   # exit 1; 4 findings
confaudit --severity high testdata/sshd/good_sshd_config  # exit 0
```

## Commands and results (audit host)

| Command | Exit | Result |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | 0 | clean |
| `cargo test --all-targets --locked` (baseline) | 0 | 142 passed, 0 failed, 0 ignored |
| `cargo test --all-targets --locked` (after) | 0 | 154 passed, 0 failed, 0 ignored |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked` (baseline) | 101 | private intra-doc links |
| same (after) | 0 | clean |
| `cargo audit --db <local advisory-db> --no-fetch` | 0 | 0 vulnerabilities |
| `cargo deny check` | — | not configured |

## False-positive / false-negative corpus

`testdata/corpus/` pins exact rule-ID sets (`tests/cli.rs::corpus_of_known_false_positives_and_negatives`).
Output of the previous release (`main`, built locally) vs. this branch:

| Fixture | `main` reported | Now | Kind of error fixed |
| --- | --- | --- | --- |
| `inheritance_trap.conf` | none | NGX006, NGX007, NGX012 | false negatives |
| `Dockerfile.multistage-good` | DOCK002 | none | false positive |
| `Dockerfile.multistage-root` | none | DOCK001 | false negative |
| `equals_sshd_config` | SSHD001 (medium, "unset"), SSHD006, SSHD007 | SSHD001 (critical) | 1 misgraded, 2 false positives |

The bundled `testdata/nginx/good.conf` itself had the nginx inheritance
bug (its TLS server's HSTS `add_header` discarded the http-level
`X-Frame-Options` / `X-Content-Type-Options`); it is corrected and now
pinned as clean at every severity.

## CI status

Default branch: `success` (run on `f010692`, 2026-08-30).
Audit branch: pending until pushed. Actions pinned by tag; unchanged.

## Bugs found and fixed (each with a regression test)

| # | Severity | Defect | Fix | Regression test |
| --- | --- | --- | --- | --- |
| 1 | High (false negative) | nginx `add_header` inheritance modelled as a union; nginx discards all inherited headers in a block with its own `add_header`. Headers set in one nested location also counted for the whole server. | Replacement semantics; dropped headers reported at the location; server coverage = server level or every top-level location. | `nginx::tests::{a_server_level_add_header_discards_inherited_security_headers, a_location_with_its_own_add_header_reports_what_it_drops, a_header_set_in_only_one_location_does_not_cover_the_server, headers_set_in_every_location_cover_the_server}` |
| 2 | High (FN + FP) | NGX012 flagged `location /x { alias /d/x; }` (not exploitable) and missed `location /x { alias /d/x/; }` (off-by-slash traversal). Existing test expectation changed accordingly. | Condition inverted on the alias slash. | `alias_off_by_slash_is_flagged_and_matching_forms_are_not`, `alias_without_trailing_slash_flagged` |
| 3 | High (FN) | Dockerfile: last `USER` of any stage used; a builder-stage `USER` hid a root final image. | Final stage only. | `dockerfile::tests::user_in_a_builder_stage_does_not_cover_the_final_stage` |
| 4 | Medium (FP) | DOCK002 on `FROM <stage>` and on `--platform=` (image never checked); any name containing "scratch" skipped. | Stage aliases tracked; flags skipped; exact `scratch`. | `stage_references_and_platform_flags_are_not_untagged_images` |
| 5 | Medium (misgrade) | sshd `Keyword=value` not parsed: `PermitRootLogin=yes` reported as unset (medium). | Split on whitespace or `=`. | `sshd::tests::keyword_equals_value_syntax_is_understood` |
| 6 | Medium (FP) | sshd `Ciphers -weak,...` (removal) reported as enabling weak algorithms. | `-` lists ignored. | `removing_weak_algorithms_is_not_flagged` |
| 7 | Docs | `cargo doc -D warnings` failed; README example summary/line did not match real output. | Fixed. | — |

Also added: `first_occurrence_wins_like_sshd` (pins existing correct behaviour).

## Security review

- `unsafe_code = "forbid"`; no network; nothing executed from input.
- Malformed input returns errors (existing tests); parsers are linear.
- Secret-shaped fixtures use obviously fake values; secret scan of the
  tree and full history: no hits.
- Workflow permissions: `contents: read`.

## Known limitations

See README "Limitations": `Include` not followed; most sshd defaults not
inferred (unset `PasswordAuthentication` not reported); nginx variables /
`map` / `if` not evaluated; `ARG` substitution in Dockerfiles not
expanded. MSRV 1.74 not run locally; `cargo deny` not configured.

## Acceptance checklist

| Item | Expected behaviour | Command / test | Result | Actual | Reference |
| --- | --- | --- | --- | --- | --- |
| Rules fire on bad configs | All three bad fixtures exit 1 with findings | clean-clone runs | pass | 13 / 14 / 4 findings | `src/parsers/` |
| Good configs clean | Good fixtures produce no findings | `good_fixtures_are_clean_at_every_severity` | pass (nginx good.conf failed before) | 0 | `testdata/` |
| Known FP/FN cases | Exact rule sets | corpus test | pass (all 4 differed before) | as table | `testdata/corpus/` |
| Parser semantics | Match scope, first-wins, `=` syntax, inheritance | unit tests | pass | — | `src/parsers/` |
| Output formats | text/JSON/SARIF valid | CLI tests, SARIF parsed | pass | SARIF 2.1.0 | `src/output/` |
| Exit codes / filters | 0/1/2, `--severity`, `--ignore`, `--no-fail` | CLI tests | pass | — | `src/main.rs` |
| Malformed input | Clean error, no panic | unit tests | pass | — | parsers |

## Classification proposal

**Partially Verified** — documented scope tested on macOS with six rule
logic defects fixed and a fixture corpus guarding them; not yet
verified: MSRV 1.74 and the audit branch's CI.

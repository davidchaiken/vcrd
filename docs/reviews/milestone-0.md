# Milestone 0 review

**Scope.** DEVELOPMENT-PLAN.md, milestone 0: the repository skeleton reviewed against
REQUIREMENTS §7, §12's supply-chain, `SECURITY.md` and CI-hardening paragraphs, and §13's
CI paragraphs, sentence by sentence. No standard is implemented yet, so no normative
specification text is reviewed here. The sentences of §5 and §6 that the milestone's scope
names are included.

**Where checked.** Branch `milestone-0`, based on `main` at `d570cc9`. Toolchain 1.98.1
(clippy 0.1.98). Locally on macOS 26.6.2, aarch64. CI on Linux and macOS is pending the
pull request's first run; rows that depend on it say so.

**Reproduce.** From the repository root, `make ci-ok` runs the four jobs CI's `ci-ok`
requires, in order: `cargo fmt --all --check`, `scripts/feature-matrix.sh`,
`scripts/check-lints-fire.sh`, then `cargo deny --locked check` and
`cargo audit --deny warnings` with the pinned tool versions built into `target/tools`.

**Status key.** *Met*: implemented, with the check that shows it. *Amended*: the sentence
changed in this milestone, and the new text is met. *Later*: belongs to the named later
milestone. *Open*: not yet shown, with what remains. *Not applicable*: nothing in the
milestone is subject to the sentence.

## REQUIREMENTS §5 and §6

| Line | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|
| §5, 265 | Once a `Cargo.toml` exists, its `license` field should read `"MIT OR Apache-2.0"`. | `[workspace.package] license`, inherited by both crates | `cargo deny --locked list --layout license`: vcrd-core and vcrd-cli listed under Apache-2.0 and MIT | Met |
| §6, 364 | `#![forbid(unsafe_code)]` in both `vcrd-core` and `vcrd-cli`. | The attribute in each crate root, and `unsafe_code = "forbid"` in `[workspace.lints.rust]` | `check-lints-fire.sh` cases 2 and 4 | Met |
| §6, 391 | `unwrap`/`expect`/panicking-index are forbidden on those paths via workspace-level clippy lints (exempted only in test code). | See §7, line 484 | See §7, line 484 | Met |

## REQUIREMENTS §7

| Line | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|
| 428 | A single Cargo workspace (resolver `"3"`, Rust 2024 edition), with `[workspace.package]` inheritance for `version`, `edition`, `license`, `authors`, and `repository`. | Root `Cargo.toml`; both members inherit the five fields, plus `rust-version` and `publish` | Every `cargo` command resolves the workspace | Amended: resolver 2 became 3, edition 2024's default, which keeps dependency choices within `rust-version`. Met |
| 432 | `vcrd-core` — the library. Owns the data model, the traits, and all parsing, inspection, and verification logic. No CLI dependencies, no `unsafe`, no ambient I/O. | The crate, with no dependencies and `unsafe` forbidden | `cargo tree -p vcrd-core -e normal` lists no dependencies; `check-lints-fire.sh` | Met for what exists. Data model and traits: Later (milestone 1) |
| 435 | `vcrd-cli` — the binary crate, depending on `vcrd-core`, owning `clap` and all presentation logic. Produces the installed `vcrd` binary. | `[[bin]] name = "vcrd"`; `clap` only in vcrd-cli | `feature-matrix.sh` runs `vcrd --help` and `vcrd --version` | Met |
| 439–460 | Deferred workspace members; the out-of-scope capture crate; signing exposed from core. | — | — | Not applicable |
| 462 | Format and proof-suite implementations live as feature-gated modules inside `vcrd-core` (e.g. `jsonld`, `vc-jose` Cargo features). | Feature `vc-jose` in vcrd-core, forwarded by vcrd-cli | `feature-matrix.sh` builds core with and without it | Amended: `jwt-vc` became `vc-jose`, because "JWT-VC" usually names the VCDM 1.1 encoding that VC-JOSE-COSE §3.1.3 forbids. Met for the feature; the module is Later (milestone 1) |
| 470 | `ProofSuite` designed with room for partial/selective-disclosure proofs. | — | — | Later (milestone 1) |
| 477 | All crates share a single workspace version via `version.workspace = true`. | Both crates | By inspection of `vcrd-*/Cargo.toml` | Met |
| 481 | This intent will be documented explicitly (e.g. in `CONTRIBUTING.md`). | — | — | Later (milestone 6, [P2]) |
| 484 | Workspace-level lints: deny `unwrap_used`, `expect_used`, and `indexing_slicing` outside test code. | `[workspace.lints.clippy]` denies those three and `string_slice`, `panic`, `todo`, `unimplemented`, `unreachable`; `clippy.toml` exempts unwrap, expect, indexing and panic in tests; each member has `[lints] workspace = true` | `check-lints-fire.sh`, 29 cases, and the faults below | Met, with gap 1 |

## REQUIREMENTS §12

| Line | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|
| 1031 | `cargo-audit` and `cargo-deny` run in CI, checking dependencies against the RustSec advisory database and enforcing license compliance. | CI job `supply chain`; `deny.toml` | `cargo deny --locked check`: "advisories ok, bans ok, licenses ok, sources ok"; `cargo audit --deny warnings`: exit 0; faults D1, D2, A1, A2 | Met locally. CI: Open (first run) |
| 1032 | `Cargo.lock` is committed and tagged at every release. | `Cargo.lock` committed; every cargo command in `scripts/` and CI passes `--locked` | By inspection | Committed: Met. Tagged: Later (milestone 6) |
| 1035 | SBOM per release, build metadata in the binary, signed and reproducible releases. | — | — | Later (after 0.1.0) |
| 1040 | Crypto dependency selection criterion. | No cryptographic dependency yet | — | Later (milestone 1) |
| 1047 | `SECURITY.md`: a reporting channel (GitHub's private security advisory feature). | `SECURITY.md`, "Reporting a vulnerability"; private vulnerability reporting enabled | Setting reported by the maintainer, 2026-09-22 | Met |
| 1049 | A best-effort/pre-1.0 response expectation rather than an SLA. | "What to expect" | By inspection | Met |
| 1050 | A "supported: main branch only" statement while pre-1.0. | "Supported versions" | By inspection | Met |
| 1050 | A pointer to the threat model. | Link to REQUIREMENTS.md §12 | By inspection | Met |
| 1051 | A plain-language reliance/liability stance: pre-1.0, not to be relied on for production trust decisions. | "Reliance on vcrd's results" | By inspection | Met |
| 1062 | Untrusted PR code never runs with secrets or write access; building and testing PR code uses plain `pull_request`. | Triggers: `pull_request`, `push` to `main`, weekly `schedule`, `workflow_dispatch`; no secrets referenced | `grep -n 'pull_request_target\|secrets\.' .github/workflows/ci.yml` finds only the file's comment | Met |
| 1066 | Privileged follow-up work runs as a separate `workflow_run` workflow that only reads artifacts. | Nothing privileged exists | — | Not applicable |
| 1070 | `GITHUB_TOKEN` permissions default to `read-all` (or narrower) at the workflow level. | `permissions: contents: read`; repository default read-only; `persist-credentials: false` on every checkout | By inspection; setting reported 2026-09-22 | Met |
| 1072 | Third-party Actions are pinned to a full commit SHA; SHA updates are proposed as reviewable PRs. | Only `actions/checkout`, GitHub-owned, pinned to `3d3c42e5…` (v7.0.1); the repository allows only GitHub-owned actions and requires full-SHA pins; `dependabot.yml` updates Actions weekly | By inspection; settings reported 2026-09-22 | Met |
| 1075 | Require approval for first-time contributors' workflow runs. | "Require approval for all external contributors" | Setting reported 2026-09-22 | Met ([P3]) |
| 1079 | Publishing credentials never touch PR-triggered workflows; Trusted Publishing preferred. | No publishing exists | — | Later (milestone 6) |
| 1083 | A `CODEOWNERS` entry requiring maintainer review on `.github/workflows/*`. | `.github/CODEOWNERS` covers `/.github/`, `/Cargo.toml`, `/Makefile`, `/clippy.toml`, `/deny.toml`, `/rust-toolchain.toml`, `/.cargo/`, `/scripts/`; the `main` ruleset requires code-owner review | — | Open: enforcement is checked after merge (below) |

## REQUIREMENTS §13

| Line | Sentence (abridged) | Mechanism | Check | Status |
|---|---|---|---|---|
| 1112 | The declared MSRV and the toolchain vcrd is built with are one pinned release, the latest stable during active development. | `rust-toolchain.toml` channel 1.98.1 equals `rust-version` | `rustup show active-toolchain`: "1.98.1-aarch64-apple-darwin (overridden by …/rust-toolchain.toml)" | Amended: the N-2 policy became the latest stable release. Met |
| 1117 | The CI jobs that must pass before a merge run the pinned release. | Jobs `fmt`, `test`, `lints fire` and `supply chain` install the toolchain named in `rust-toolchain.toml`; `ci-ok` needs exactly these | By inspection | Met. CI: Open (first run) |
| 1118 | A further job runs the latest stable release and does not block a merge. | Job `test (…, latest stable)` with `RUSTUP_TOOLCHAIN: stable`; not in `ci-ok`'s `needs` | By inspection | Met. CI: Open (first run) |
| 1120 | Nightly is reserved for the future `cargo-fuzz` job. | No nightly toolchain in CI | By inspection | Met |
| 1122 | CI platforms: Linux and macOS initially; Windows left open. | `os: [ubuntu-latest, macos-latest]` | macOS locally | macOS: Met. Linux: Open (first run) |
| 1124 | CI builds and tests each supported combination of features, not only the default set. | `scripts/feature-matrix.sh`: vcrd-core with every combination of `vc-jose` and `std-clock`, vcrd-cli default, and vcrd-cli with no format, which must fail with the `compile_error!` message | Local run: "Every feature combination passed."; fault M6 | Met. CI: Open (first run) |

## DEVELOPMENT-PLAN milestone 0

| Item | Check | Status |
|---|---|---|
| `vcrd --help` and `vcrd --version` build on both platforms. | `feature-matrix.sh`; `vcrd --version` prints `vcrd 0.0.0` | macOS: Met. Linux: Open (first run) |
| `cargo test --workspace` green with no tests. | `cargo test --workspace --locked` | Met |
| `cargo clippy --all-targets` clean, with the lint confirmed to fire. | `feature-matrix.sh`; `check-lints-fire.sh` | Met |
| CI green on every matrix cell. | The pull request's checks | Open (first run) |
| The lint-fires check recorded as a CI step rather than a memory. | CI job `lints fire` | Met |

## The checks shown to fail

REQUIREMENTS §11 holds that a check which has never failed has not shown that it detects
anything. Each check was run against a copy of the repository with one fault planted, and
failed; then against the unmodified copy, and passed. The working tree was not modified.

| # | Fault planted | Check | Result |
|---|---|---|---|
| M1 | `vcrd-core/Cargo.toml` without `[lints] workspace = true` | `check-lints-fire.sh` | `FAIL: unwrap_used denied in vcrd-core/src/lib.rs: clippy passed` |
| M2 | vcrd-cli missing from `[workspace.metadata.lints-fire]` | `check-lints-fire.sh` | `FAIL: workspace member vcrd-cli has no root in [workspace.metadata.lints-fire]` |
| M3 | `clippy.toml` without `allow-panic-in-tests` | `check-lints-fire.sh` | `FAIL: unwrap, expect, indexing and panic exempt in #[cfg(test)] modules and tests/*.rs: clippy failed` |
| M4 | `vcrd-cli/src/main.rs` without `#![forbid(unsafe_code)]` | `check-lints-fire.sh` | `FAIL: vcrd-cli/src/main.rs lacks #![forbid(unsafe_code)]` (after the fix in gap 2) |
| M5 | `Cargo.toml` without `unsafe_code = "forbid"` | `check-lints-fire.sh` | `FAIL: Cargo.toml lacks unsafe_code = "forbid"` |
| M6 | vcrd-cli without its `#[cfg]` and `compile_error!` | `feature-matrix.sh` | `FAIL: vcrd-cli built with no format feature` |
| D1 | `deny.toml` without `Unicode-3.0` | `cargo deny check licenses` | `licenses FAILED` (unicode-ident) |
| D2 | `clap` taken from its git repository | `cargo deny check sources` | `sources FAILED`: "detected 'git' source not explicitly allowed" |
| A1 | A dependency on `atty` 0.2.14 | `cargo deny check advisories` | `advisories FAILED`: RUSTSEC-2021-0145 (unsound), RUSTSEC-2024-0375 (unmaintained) |
| A2 | The same | `cargo audit --deny warnings` | Exit 1, naming the same two advisories |

## Gaps found

1. **A helper function in an integration test gets no exemption.** Clippy 0.1.98 exempts
   a `#[test]` function in `tests/*.rs`, but not a helper beside it: `fn helper(v: &[u8]) ->
   u8 { v[0] }` in `vcrd-cli/tests/lint_canary.rs` fails with `indexing_slicing`. This is
   stricter than §7 asks, not a violation of it. Decide in milestone 1, with the first
   integration tests: write helpers without panicking operations, put them in
   `#[cfg(test)]` modules, or allow the four exempt lints at the top of each `tests/*.rs`.
2. **The lint-fires check misread a lint set from `Cargo.toml`.** Found by fault M4. With
   the crate attribute removed, the `unsafe` block was still rejected, reported as
   `` requested on the command line with `-F unsafe-code` ``, but the script searched only
   for the attribute's wording and reported a failure for the wrong reason. Fixed in the
   script's `expect_fail`; M4 and M5 then failed at the static check, as designed.
3. **`clap`'s usage-error exit status is 2**, which ARCHITECTURE §6 assigns to a parse
   failure: `vcrd --no-such-flag` exits 2 today. Already scheduled: DEVELOPMENT-PLAN
   milestone 1, *Output*.
4. **`feature-matrix.sh` ran `target/debug/vcrd` whatever `CARGO_TARGET_DIR` said.** Found
   in the final review. With the variable set, the script ran a stale binary if one was
   there, and passed for the wrong reason; in a copy with no `target/debug` it failed with
   "target/debug/vcrd: No such file or directory". Fixed by asking `cargo metadata` for
   the target directory; the same copy then passed.

## Open after merge

1. Record the first CI run's result for each job in this document.
2. Reconfirm the `main` ruleset, and add `ci-ok` as its required status check. The
   ruleset's check picker lists only checks that have run.
3. Open a throwaway pull request that changes only a file under `.github/`, and confirm
   that merging it requires the bypass. Whether "Require review from Code Owners" demands
   an owner's approval when zero approvals are required is not yet verified.

## Repository settings

A setting leaves no file to cite, so the settings milestone 0 depends on are recorded here,
as reported by the maintainer on 2026-09-22:

- **Actions permissions:** actions and reusable workflows from davidchaiken and selected
  others; actions created by GitHub allowed; Marketplace verified creators not allowed;
  actions must be pinned to a full-length commit SHA.
- **Fork pull request workflows:** require approval for all external contributors.
- **Workflow permissions:** read repository contents and packages; GitHub Actions may not
  create or approve pull requests.
- **Security:** private vulnerability reporting enabled; Dependabot alerts, malware
  alerts, security updates and grouped security updates enabled.
- **`main` ruleset:** created 2026-09-23; reconfirmed after merge (open item 2).

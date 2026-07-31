# vcrd Requirements & Design Document

## 1. Vision & Goals

vcrd is a tool for reading — and, over time, validating, verifying, and eventually
creating/editing — verifiable credentials (VCs). The long-term ambition is broad,
growing support for the many credential formats and proof types in use across the
identity ecosystem, built up the way mature domain tools accumulate breadth: through
sustained investment and, ideally, community contribution rather than one person doing
all of the work indefinitely.

Goals:

- **Usable across a wide range of audiences.** A novice should get useful, safe-by-default
  behavior with no flags. An expert should be able to script and compose vcrd tightly. An
  AI agent consuming vcrd's output should get stable, structured data it can parse without
  guesswork.
- **Well documented.** Documentation is treated as a first-class deliverable, not an
  afterthought — see §12.
- **Free and open source**, licensed to make both use and contribution as unencumbered as
  possible — see §4.
- **Built for community contribution from day one**, not retrofitted later. Where the
  maintainer doesn't personally need something — platform support (e.g. Windows) is the
  running example — the project should make it easy for a contributor to add it, rather
  than treating the gap as an apology.

**Explicit non-goal, stated up front because it shapes everything else:** vcrd does not
decide whether a credential should be *trusted* in a given risk context. A separate,
future program is planned to provide that kind of risk-based guidance, consuming vcrd as
a library or via its structured output. vcrd stays deliberately low-level and
unopinionated about that use case — it reports facts (this parses, this validates, this
verifies against this key material) and leaves judgment to whatever is built on top.

## 2. Background: What Is a Verifiable Credential?

This section exists so a reader unfamiliar with the domain can follow the rest of the
document without external references.

A **verifiable credential** is a set of claims made by an **issuer** about a **subject**,
packaged with metadata and cryptographically signed so that a **verifier** (relying
party) can check who made the claims and whether the package has been tampered with since
signing. The word "credential" is used more broadly here than in everyday speech — it
covers anything from a government-issued ID to a professional certification to a
membership claim, as long as it's structured and signed this way.

Three roles recur throughout this domain:

- **Issuer** — creates and cryptographically signs the credential.
- **Holder** — possesses the credential (often via a "wallet") and presents it to
  verifiers, sometimes selectively disclosing only some of its claims.
- **Verifier** — checks a presented credential's structure and signature(s), and (outside
  vcrd's scope) decides whether to trust it.

vcrd's initial scope is entirely on the verifier/inspector side: reading and checking
credentials that already exist. Creating and editing them is a later phase (§9).

The dominant data model is the **W3C Verifiable Credentials Data Model** (versions 1.1 and
2.0), which describes a credential as a JSON(-LD) document containing claims plus
metadata (issuer, issuance/expiration dates, credential type, `@context`/schema) plus one
or more **proofs**. Proof mechanisms vary significantly:

- **Data Integrity proofs** — embedded signatures over a JSON-LD document, using a
  registered "cryptosuite" (e.g. an EdDSA-based suite).
- **VC-JWT** — the credential is encoded as a JSON Web Token, signature verification
  follows standard JOSE/JWS mechanics.
- **SD-JWT VC** — a JWT-based format designed for selective disclosure: a holder can
  reveal a subset of claims without invalidating the issuer's signature.
- **AnonCreds / BBS+ (optionally with Bulletproofs)** — privacy-preserving schemes that
  allow a holder to prove facts about claims (including range predicates, e.g. "over 18")
  without revealing the underlying values at all.

Credentials reference issuer and subject identities, typically via **Decentralized
Identifiers (DIDs)**. Resolving a DID to usable key material is either self-contained (no
network needed — e.g. `did:key`, or a JWK embedded directly in the credential) or requires
a network lookup (e.g. `did:web`). This distinction matters a great deal for vcrd, because
of the no-network-by-default principle in §5.

## 3. Terminology

vcrd distinguishes four tiers of operation, each with different guarantees and different
network/trust implications:

1. **Parse** — is this input syntactically a credential in a format vcrd understands
   (valid JSON-LD/JWT/CBOR structure, etc.)? No semantic checking.
2. **Validate** — does the parsed structure conform to the relevant data model (required
   fields present, dates well-formed, `@context`/schema correct)? No cryptography
   involved, no network required — always available, always fast.
3. **Verify** — does the cryptographic proof check out against the issuer's key material?
   This splits further:
   - *Offline verification* — key material is self-contained (`did:key`, an embedded JWK)
     or resolvable from a local cache. No network call needed.
   - *Network-dependent verification* — key material requires resolving a DID via a
     method that needs a network round-trip (e.g. `did:web`), or requires checking a
     remotely-hosted revocation/status list.
4. **Trust evaluation** *(explicitly out of scope for vcrd)* — deciding whether a
   successfully verified credential should actually be relied upon, given a specific risk
   context: issuer reputation, schema appropriateness for the use case, how fresh a
   revocation check needs to be, etc. This is the job of the separate future tool
   described in §1.

"Read-only, no-network by default" (§5) means: parse and validate are always available.
Verify is available offline only for self-contained key material; network-dependent
verification requires an explicit opt-in.

## 4. Language, Licensing, Naming & IP Policy

**Language: Rust.** Chosen because it lets the no-network-by-default and read-only-by-
default principles be enforced structurally (a capability like network access can be made
impossible to reach without being deliberately threaded through), because it produces a
single distributable binary (no runtime dependency for end users), because it has a clear
path to WASM for a future browser-extension frontend, and because a meaningful and
growing share of cryptographic and identity-ecosystem work — including exactly the
BBS+/Bulletproofs territory vcrd is interested in — is happening in Rust.

**License: dual MIT/Apache-2.0**, following the standard Rust ecosystem convention (the
same pattern used by `serde`, `tokio`, and the Rust compiler itself):

- `LICENSE-APACHE` and `LICENSE-MIT` at the repo root, both already in place.
- A short statement in the README (already added) that contributions are dual-licensed
  under the same terms unless stated otherwise.
- Once a `Cargo.toml` exists, its `license` field should read `"MIT OR Apache-2.0"` (an
  SPDX expression) — this is what crates.io and tooling like `cargo-deny` actually read;
  GitHub's own "License" sidebar badge may only reflect one of the two files, which is a
  cosmetic limitation of its detection tooling, not a problem with the licensing itself.

**IP policy:** to the extent vcrd ever needs to interact with proprietary or
restricted-license code (a patented algorithm, a dependency that isn't OSS-compatible),
that code must be isolated as an optional external module or plugin — never bundled into
or required by the open-source core. The trait-based extension architecture (§6) is what
makes this possible without needing a special-case mechanism: an optional proprietary
`ProofSuite` implementation, for example, could live entirely outside this repository as
its own crate.

**Naming.** The project is named `vcrd`, pronounced "vee-cred" — short for "Verifiable
CReDential." This is worth stating explicitly since it isn't self-evident from the letters
alone. Trait names used elsewhere in this document, such as `ProofSuite` and
`CredentialFormat`, are original names chosen for this project's own design — they are not
references to any proprietary or third-party API. (The closest analog in the standards
world is the W3C Data Integrity specification's "cryptosuite" registry concept, which is
itself an open standard.)

## 5. Core Design Principles

These are the rules that keep the rest of the design coherent. Several of them exist
specifically because vcrd is meant to be consumed by more than one kind of frontend
(§6) — a rule that only works for the CLI isn't really a vcrd-core rule.

- **Read-only, no-network by default.** Any operation that would write data or make a
  network call requires an explicit, per-operation opt-in. This is the tool's most basic
  safety property and should be true even for a first-time user who reads no
  documentation.
- **`vcrd-core` takes its dependencies explicitly, rather than reaching for ambient
  state.** Concretely: a controllable clock is passed in (`now: DateTime`) rather than
  calling `SystemTime::now()`; randomness needed for proof generation is passed in via an
  `RngCore` rather than reaching for `OsRng` directly; DID resolution and JSON-LD
  `@context` document loading go through injectable resolver/loader traits, defaulting to
  a local vendored cache rather than a silent HTTP fetch. This is what makes "no network,
  fully offline, deterministic" something that can actually be verified rather than just
  hoped for, and it's what makes unit tests fast and non-flaky (§10) without mocking
  system-level facilities.
- **`vcrd-core` operations must be low-latency by construction.** An operation belongs in
  core only if its cost scales with the size of the single credential/input being
  processed — not with how many things are being processed. Anything whose cost scales
  with *count* (a directory of files, a batch of network lookups) is presumptively a
  frontend concern and must be explicitly discussed before it's allowed into core. This
  keeps the "vcrd-core doesn't need progress reporting because it should always be fast"
  property true by design rather than by accident.
- **`vcrd-core` stays UI-agnostic and unopinionated.** Errors and results are structured,
  locale-independent data — not pre-formatted English sentences, and not bare
  booleans/severity codes. This is what lets any frontend (the CLI, a future browser
  extension, a third-party Rust program) render, localize, or build an accessible
  presentation on top, rather than being stuck with whatever choice core happened to make.
  The same principle applies to two specific capabilities: progress reporting and
  diagnostic/build-info are hooks that core exposes, not things core renders — `vcrd-cli`
  is one consumer of those hooks among others that may exist later.
- **No `unsafe` code.** `#![forbid(unsafe_code)]` in both `vcrd-core` and `vcrd-cli`.
  There's no principled reason this domain logic needs it, and forbidding it is a
  compile-time guarantee rather than a review habit.
- **Dependency policy**, applied per-dependency rather than as a blanket rule:
  - *Cryptographic primitives*: always depend on well-audited crates, never reimplement.
    Prefer crates that explicitly document constant-time/side-channel handling; any that
    don't get flagged individually as a watch/upgrade/replace candidate at the point
    they're actually selected.
  - *Ecosystem-standard infrastructure* (`clap`, `serde`, etc.): always depend, no
    reimplementation debate.
  - *Domain-specific format/spec logic*: decided case-by-case, weighing implementation
    effort saved against ongoing maintenance burden (tracking upstream, absorbing breaking
    changes) — with a foreign-language (FFI) dependency penalized in that calculation,
    since it breaks single-binary distribution and complicates cross-compilation in a way
    a pure-Rust reimplementation against a written spec does not.
- **No panics on untrusted input.** Every code path that touches externally-supplied bytes
  returns `Result`; `unwrap`/`expect`/panicking-index are forbidden on those paths via
  workspace-level clippy lints (exempted only in test code). This matters because vcrd's
  entire purpose is processing credentials from parties that aren't trusted — a malicious
  or malformed credential is a realistic input even for a purely local CLI invocation.
- **Structural resource limits, not timeouts.** Every untrusted-input code path enforces
  explicit limits on size, nesting depth, and iteration/recursion count, externalized as
  configuration with conservative defaults derived from measurement (not guessed).
  Deliberately *not* included: built-in wall-clock timeouts, memory ceilings, or network
  limits. A timeout is a symptom-level control — it doesn't bound the resources consumed
  before it fires, and it's a sign the underlying complexity isn't actually understood.
  Those operational ceilings are left to external sandboxes or process supervisors, which
  already solve this well.

## 6. Architecture / Workspace Layout

A single Cargo workspace (resolver `"2"`, Rust 2024 edition), with `[workspace.package]`
inheritance for `version`, `edition`, `license`, `authors`, and `repository` so member
crates don't repeat this metadata.

- **`vcrd-core`** — the library. Owns the data model, the `CredentialFormat` and
  `ProofSuite` traits, and all parsing/validation/verification logic. No CLI dependencies,
  no `unsafe`, no ambient I/O (§5).
- **`vcrd-cli`** — the binary crate, depending on `vcrd-core`, owning `clap` and all
  presentation logic. Produces the installed `vcrd` binary (crate name and binary name can
  differ, the same way the `ripgrep` crate produces the `rg` binary, if that turns out to
  be convenient).
- **Deferred, future workspace members**: `vcrd-net` (network/tcpdump-style capture) and
  `vcrd-wasm`/`vcrd-browser` (a browser extension, most likely a thin shell around a
  WASM-compiled `vcrd-core`). Both are additional consumers of `vcrd-core` as a library,
  not modifications to it — reinforcing why core must stay origin-agnostic (§8).

**Format and proof-suite implementations live as feature-gated modules inside
`vcrd-core`** (e.g. `jsonld`, `jwt-vc` Cargo features), not as separate per-format crates.
This was a deliberate choice to avoid premature architecture: splitting a module out into
its own crate later, if an external contributor wants to ship one independently, doesn't
require breaking the trait contract that already exists. The trait boundary is what
provides extensibility; crate-level separation is an implementation detail that can follow
demand rather than precede it.

Note for `ProofSuite` specifically: because AnonCreds/BBS+ (with optional Bulletproofs
range proofs, §9) involve proofs that reveal only a subset of claims rather than a simple
"verify a signature over these exact bytes" operation, the trait should be designed with
room for partial/selective-disclosure proofs from the start, even though those formats
aren't implemented first. Retrofitting that shape after the trait is load-bearing API
would be far more disruptive than designing for it now.

**Versioning**: all crates currently share a single workspace version via
`version.workspace = true`. This is intentional for now (single maintainer, no reason for
crates to diverge), but the mechanism already supports splitting — moving a crate to an
independent version later is a one-line change (drop `.workspace = true`, set a literal
version), not a restructuring. Worth documenting this intent explicitly (e.g. in
`CONTRIBUTING.md`) so a future split doesn't look accidental.

**Workspace-level lints** (`[workspace.lints.clippy]`): deny `unwrap_used`, `expect_used`,
and `indexing_slicing` outside test code, enforcing the no-panic-on-untrusted-input rule
from §5. This also sets up future fuzzing (§10) to be meaningful — a fuzzer finding "this
panics" is only useful if panics were supposed to be impossible.

## 7. CLI Design

`vcrd-cli` breaks deliberately from older single-command, flag-heavy CLI conventions in
favor of a verb-first subcommand structure, in the style of tools like `cosign`, `age`,
`gh`, and `cargo`:

- `vcrd inspect <file>` — parse + validate, human-readable by default.
- `vcrd validate <file>`
- `vcrd verify <file>` — offline-only unless `--allow-network` is passed; this flag is
  global, not per-subcommand, so it can't be missed.
- `vcrd formats` / `vcrd suites` — list supported credential formats and proof suites
  (discoverable capability probing, useful for both humans and agents).

**Defaults matter.** Running `vcrd <file>` with no subcommand, or piping input via
`cat file | vcrd`, defaults to `inspect` at the default verbosity level — a novice gets a
useful answer without reading documentation first.

**Cross-cutting flags**: `--verbose`/`--verbosity` (diagnostic detail level) and
`--format json|text|plain` (output shape). stdout is reserved for the actual result (so
output stays pipeable); stderr carries diagnostics and progress. Distinct exit codes
distinguish parse failure, validation failure, and verification failure, so a calling
script can branch on which kind of failure occurred rather than just "something went
wrong."

**`clap`** (derive macros) handles argument parsing, `--help` generation, shell completion
generation, and man-page generation (`clap_mangen`) — all close to free once the argument
structs are defined, and all automatically stay in sync with actual CLI behavior rather
than drifting like hand-maintained docs would.

**Accessibility conventions**: pass/fail is never signaled by color alone (always paired
with text — "PASS"/"FAIL", not just a colored symbol), and the `NO_COLOR` environment
variable convention is honored.

**Progress reporting** is a frontend concern, not a core one, per §5 — and ideally
`vcrd-core` never needs it at all, since its operations are meant to stay fast by
construction. Where a *frontend* offers a genuinely long-running feature (the running
example is a recursive filesystem scan across many credential files), the design is a
producer/consumer split: a fast enumerator (the `ignore` crate, the same one `ripgrep`/
`fd` are built on, handles fast parallel-aware directory walking) establishes a total
count quickly, while a worker pool processes files and reports progress against that
total, rendered via `indicatif`. This stays thread-based (plain threads or `rayon`) rather
than pulling in an async runtime — the workload here is CPU/filesystem-bound, not
concurrent-network-I/O-bound, and there's no concrete driver yet for the complexity an
async runtime would add. Progress rendering is TTY-aware: suppressed or replaced by
structured events when output is piped or `--format json` is requested, so an agent
consuming JSON on stdout never has a progress bar corrupting it.

**Open design question, not yet resolved:** `vcrd --version --verbose` (or similar) is
meant to expose diagnostic/build information for bug reports — but it needs to be
designed as a `vcrd-core`-level capability first, with the CLI as one renderer of it, not
a CLI-only feature. This is because `vcrd-core` is explicitly meant to be usable
independently of the CLI (as a library, and eventually via a WASM frontend) — a consumer
who never runs the `vcrd` binary still needs a way to produce good bug-report diagnostics.
Separately, the *content* of that output still needs scoping: an ordinary bug report
probably wants a short block (vcrd version, rustc version, target triple, commit hash),
while a full dependency/SBOM-style manifest (useful for supply-chain verification, §11) is
likely too much noise for that use case and probably belongs behind a separate, explicit
command instead of folded into general `--verbose`. Both of these are open items — see
§14.

## 8. Input/Output Modalities

**Input**: files and stdin/pipes are the initial supported modalities. Network capture
(tcpdump-style) and a browser extension are explicitly anticipated but deferred to
separate crates (§6). `vcrd-core`'s functions take bytes in and don't know or care where
those bytes came from — that's what lets every current and future frontend share the same
core logic.

**Output**: structured JSON, well-formatted human-readable text, and unformatted/plain
text are the three initial formats. JSON deliberately doubles as the agent-facing format
— there is no separate "agent mode" output, and no natural-language summarization baked
into vcrd itself. This is intentional: the future risk/trust-advice tool (§1) is meant to
be built on top of vcrd, and vcrd staying unopinionated about that higher-level use case
means it shouldn't bake in assumptions about what such a system needs. Plain structured
JSON is the more general, more reusable choice.

## 9. Initial Format & Verification Scope

Initial format support: **JSON-LD with Data Integrity proofs**, plus **one JWT-based VC
format** — chosen as the starting pair specifically because they keep the first
implementation understandable and testable, not because they're the only formats vcrd
cares about. (The exact JWT-based format to implement first is an implementation-time
decision, not pinned here.)

Near/medium-term roadmap: **SD-JWT VC**, given its real-world adoption in wallet
ecosystems.

Named future direction, deliberately not built first: **AnonCreds and BBS+ signatures,
optionally combined with Bulletproofs for zero-knowledge range proofs.** This is a
different verification paradigm from a simple signature check (§2, §6) and is the reason
`ProofSuite` needs to anticipate partial/selective-disclosure proofs architecturally, even
before it's implemented. Relevant open-source prior art in Rust: Hyperledger's
`anoncreds-rs` (the official successor to the older `libindy`/`ursa` stack) and Dock's
`proof-system`/crypto crates, which already implement BBS+ with bulletproofs-style range
proofs.

Noted but deprioritized: **mdoc/mDL** (ISO 18013-5) — partly because official ISO test
vectors are not freely/openly licensed, which would complicate building an open
conformance suite around it the way the W3C-based formats allow.

**DID resolution** starts with offline-resolvable methods (`did:key`, embedded JWKs);
network-dependent resolution (`did:web` and similar) is available only with the
`--allow-network` opt-in described in §7.

**Explicitly out of scope for this phase**: issuing and editing credentials (a later
phase built on the same core), and the risk-based trust-advice layer described in §1
(a separate program entirely).

## 10. Testing Strategy

- **Unit tests** live alongside the code they test in `vcrd-core`, and must run fully
  offline with no external-state dependencies — no network, no reliance on system clock,
  no ambient filesystem/environment coupling (§5 makes this possible by construction
  rather than by test-time mocking).
- **CLI black-box tests** live in `vcrd-cli`, using `assert_cmd`/`predicates` to exercise
  the actual binary's stdout/stderr/exit-code behavior.
- **Conformance tests** run against vendored (copied into the repo, not git-submoduled)
  static fixture files drawn from the W3C VC Test Suite, the DID Test Suite, and RDF
  Dataset Canonicalization (URDNA2015/RDFC-1.0) test vectors. Each vendored fixture's
  source and license should be tracked (source repo + commit/tag), since redistribution
  rights aren't automatically safe to assume — this matters more for any future mdoc/ISO
  material, where paywalled standards could actually block vendoring vectors at all.
  Where a conformance suite (notably the W3C VC Test Suite) assumes an HTTP-based
  "VC-API" test harness rather than direct library calls, the resolution approach is
  deliberately deferred to a two-branch implementation spike (§14) rather than decided in
  the abstract.
- **Negative and adversarial fixtures are a required category, not an afterthought.**
  Given vcrd's whole purpose is trust-relevant checking, "known-good credential verifies
  successfully" fixtures are the less important half of the test matrix. Required
  coverage includes: expired, not-yet-valid, revoked, tampered-signature, wrong-issuer,
  and malformed-`@context` cases, plus — specifically — **algorithm-confusion attacks**
  (e.g. tricking a verifier expecting RS256 into accepting an HMAC-signed token using the
  public key as the secret, or accepting `alg: none`). This class of bug has repeatedly
  and concretely affected real JWT/JOSE implementations and needs to be a named test
  category from the start, since vcrd implements verification itself rather than wrapping
  an already-hardened library.
- **Property-based tests** (`proptest`) are included from the start alongside unit tests
  — round-trip (`parse(serialize(x)) == x`) and invariant (canonicalization idempotency)
  checks catch a different class of bug than example-based tests and are cheap to add as
  core modules are built.
- **Fuzzing** (`cargo-fuzz`) is deferred to implementation time, but the workspace is
  prepared for it now: the no-panic-on-untrusted-input lint policy (§5, §6) is what makes
  a fuzz target meaningful, and the same vendored conformance fixtures will double as seed
  corpus. The `fuzz/` directory, when added, is excluded from the main workspace since it
  needs a nightly toolchain.
- **Externalized state for determinism**, beyond just the clock (§5): randomness used in
  proof generation is injectable (relevant specifically for BBS+/Bulletproofs, where
  proof generation itself consumes randomness, not just key generation); DID resolution
  and JSON-LD context loading go through injectable resolvers/loaders defaulting to local
  fixtures; output formatting uses a fixed locale rather than inheriting system locale;
  no process-global mutable caches (which would let parallel `cargo test` runs interfere
  with each other); no library-level reads of environment variables (pushed to the CLI's
  argument-parsing layer, which is already covered by black-box tests).
- **Performance testing** is split in two, specifically to avoid a *different* kind of
  test flakiness than external-state flakiness: a loose, absolute-threshold smoke test in
  the normal suite (a tripwire generous enough to never spuriously fail on a slow CI
  runner, but tight enough to catch a gross regression like an accidental unbounded loop),
  plus separate `criterion` benchmarks for actual performance tracking. `criterion` is
  used here specifically because it compares against a stored statistical baseline rather
  than a bare wall-clock threshold, which is what avoids CI-machine-variance flakiness;
  it's also itself dual MIT/Apache-2.0 licensed. Benchmarks are run on demand or on a
  schedule, not as a PR gate.
- **Code coverage** is measured via `cargo-llvm-cov` and treated as a visible signal in PR
  review — a ratchet, not a hard automated gate. The policy (to be stated in
  `CONTRIBUTING.md`) is: not adamant about 100%, but a PR that decreases overall coverage
  should prompt discussion of whether that's a real gap or an acceptable trade-off, not be
  auto-rejected. Coverage is a signal, not proof of correctness, and shouldn't be gamed
  with tests that execute a line without asserting anything meaningful. If Codecov is used
  for reporting, it must be wired in via their official GitHub Action pinned to a commit
  SHA — not a `curl | bash` uploader script, which was the actual vector in a real 2021
  supply-chain compromise that used Codecov's bash uploader to exfiltrate CI secrets from
  downstream projects.

## 11. Security Posture

**Threat model (lightweight, to be promoted to `docs/threat-model.md` once implementation
is further along):**

- **Adversary**: a malicious or careless credential issuer or holder, attempting either
  to get vcrd to report a false "valid"/"verified" result, or to crash or exploit vcrd via
  a malformed or adversarially-crafted credential file. vcrd's core purpose — checking
  credentials from parties that aren't trusted — makes this a realistic threat even for a
  purely local, offline CLI invocation, not a hypothetical one.
- **In scope now**: parsing, validation, and verification correctness (including the
  algorithm-confusion and malformed-input categories named in §10); resource exhaustion
  via oversized or pathologically-structured input (§5's structural limits); memory
  safety (addressed largely for free by Rust plus the `#![forbid(unsafe_code)]` policy).
- **Explicitly deferred, named so the gap is deliberate rather than accidental**:
  network-facing attack scenarios (out of scope while network access stays opt-in and
  off by default); secret-key handling and storage (verification primarily operates on
  public key material; this becomes relevant once issuance — §9 — enters scope, since
  that involves private signing keys).

**Supply chain**: `cargo-audit` and `cargo-deny` run in CI, checking dependencies against
the RustSec advisory database and enforcing license compliance. `Cargo.lock` is committed
and tagged at every release (workspace crates produce an installed binary, so pinning
exact versions is standard practice here even though a library-only crate typically
wouldn't commit its lockfile). Longer-term, not needed immediately: publishing a
Software Bill of Materials per release (`cargo cyclonedx` or similar), baking build/
dependency metadata into the binary itself so it's self-reporting even without source
access (tying into the diagnostic API discussed in §7), and signed/reproducible releases.

**Crypto dependency selection criterion**: prefer crates that explicitly document
constant-time/side-channel handling (RustCrypto and `dalek-cryptography` crates generally
do, and the `subtle` crate exists specifically to give this ecosystem constant-time
primitives to build on). Any crate selected despite not documenting this gets named
individually as a watch/upgrade/replace candidate at the point it's chosen — this is a
selection-time policy, not a task to track before any crate has actually been picked.

**`SECURITY.md`**, present from the start of the project: a reporting channel (GitHub's
private security advisory feature, avoiding separate email infrastructure), an honest
best-effort/pre-1.0 response expectation rather than an SLA that can't be backed, a
"supported: main branch only" statement while pre-1.0, and a pointer to the threat model
above.

**GitHub Actions / CI hardening**, adopted immediately even while the project is
solo-maintained, since retrofitting these habits after bad patterns are established (or
after an incident) is far more painful than starting clean:

- Untrusted PR code never runs with secrets or write access. The dangerous trigger is
  `pull_request_target`, which runs with the base repo's token/secrets but can be pointed
  at the PR's own (attacker-controlled) code — this exact pattern has caused real,
  publicized secret-exfiltration incidents elsewhere. Anything that builds/tests/runs PR
  code uses plain `pull_request` (read-only token, no secrets for fork PRs by default). If
  something privileged needs to happen based on a PR's results (e.g. posting a comment), it
  runs as a separate `workflow_run`-triggered workflow that only reads artifacts — it never
  executes the PR's code.
- `GITHUB_TOKEN` permissions default to `read-all` (or narrower) at the workflow level;
  specific jobs get specific write scopes only when they actually need them.
- Third-party Actions are pinned to a full commit SHA, not a mutable tag — a tag can be
  moved by a compromised maintainer account, which has happened to popular Actions before.
  SHA updates are proposed as reviewable PRs (Dependabot or similar), not tracked manually.
- **Require approval for first-time contributors' workflow runs** — a repo setting
  (Settings → Actions → General → Fork pull request workflows), enabled from the start
  since it costs nothing while solo and closes off a PR-based abuse vector before there's
  any PR traffic to review under time pressure.
- Publishing credentials (crates.io, GitHub releases) never touch PR-triggered workflows
  — only trusted events like a maintainer's tag push. crates.io's Trusted Publishing
  (OIDC-based, no long-lived API token stored as a secret) is preferred over a classic
  token once release automation is built.
- **A `CODEOWNERS` entry requiring maintainer review on `.github/workflows/*`**, enabled
  from the start for the same reason as the approval setting above — it prevents a
  malicious workflow-file change from being buried inside an otherwise-unrelated-looking
  PR, once there's more than one contributor.

## 12. Release, Versioning & Documentation Tooling

- **SemVer**: vcrd follows Cargo's own pre-1.0 convention explicitly (stated here rather
  than left to assumption) — `0.x.y → 0.x.(y+1)` is treated as non-breaking, `0.x.y →
  0.(x+1).0` as potentially breaking, rather than strict SemVer's "everything pre-1.0 is
  unstable" reading.
- **`cargo-semver-checks`** is added to CI once `vcrd-core`'s public API has stabilized
  enough to be worth protecting, and in any case before 1.0 — it diffs the public API
  against the last published version and flags accidental breaking changes.
- **Publishing**: `vcrd-core` goes to crates.io normally, which gets free API docs on
  docs.rs with no extra effort beyond writing good doc comments. `vcrd-cli` is published
  to crates.io as well, and — once there's release infrastructure to build — distributed
  as prebuilt cross-platform binaries via `cargo-dist`, which also covers SBOM generation
  and checksums as part of the same pipeline (tying back to §11's supply-chain goals).
- **Documentation**: CLI reference documentation and man pages are generated directly from
  the `clap` argument definitions (`clap_mangen` and similar), so they can't drift out of
  sync with actual CLI behavior the way hand-maintained docs would. README + doc comments
  + this generated CLI reference are sufficient for now; a higher-level conceptual guide
  (mdBook-style) is deferred until there's enough real surface area to justify the
  investment.
- **Branching / release cadence**: trunk-based development — work happens on `main` with
  short-lived branches for PRs and experiments, no long-lived release branches, until
  there's a concrete need to maintain more than one release line at once (e.g.
  backporting a security fix to an old major version).
- **CI Rust versions**: CI runs on latest stable, plus a second job pinned to the declared
  MSRV, to actually verify the MSRV policy holds (it's easy to accidentally use a newer
  API without noticing on a stable-only CI matrix). MSRV policy is **current stable minus
  two releases (N-2)**, stated as prose rather than heavily automated — the goal is
  avoiding a treadmill of updating a hard-pinned number every ~6-week stable release, with
  the option to move to a time-based policy later being a documentation change, not a
  structural one. Nightly is reserved for the future `cargo-fuzz` job (needs nightly for
  `libfuzzer-sys`), not part of normal CI.
- **CI platforms**: Linux and macOS initially. Windows CI is deliberately left as an open
  community-contribution opportunity, consistent with §1's stance on platform support.

## 13. Contribution & Community Structure

Kept deliberately light while the project is solo-maintained — the right frame is "rules
the maintainer already follows, written down now so they apply to any future
contributor," not a heavyweight process built in advance of needing one.

- **`CONTRIBUTING.md`** covers: local build/test commands; the PR workflow (short-lived
  branch off `main`); a pointer to the trait-based extension points in `vcrd-core`
  (`CredentialFormat`, `ProofSuite`) as the main on-ramp for a contribution, since adding
  a new format/suite is the most likely thing an outside contributor wants to do; an
  explicit, welcoming note that platform support (Windows, etc.) is open territory rather
  than an apologized-for gap; and a pointer to `SECURITY.md` for vulnerability reports
  rather than the public issue tracker.
- **Issue and PR templates**: a bug report template nudges reporters to include vcrd's
  diagnostic/version output (§7), and explicitly warns against pasting a real, live
  credential into a public GitHub issue — VCs can carry real personal data, and encouraging
  synthetic/test fixtures instead is a deliberate norm for a tool whose whole purpose is
  handling this kind of data carefully. A PR template checklist covers: tests pass
  offline, `clippy`/`fmt` clean, and flags changes touching `.github/workflows/` or adding
  a new dependency for extra scrutiny (§11).
- **`CODE_OF_CONDUCT.md`** adopts the Contributor Covenant as-is, rather than a
  custom-authored document — it's the de facto standard across the Rust ecosystem and
  contributors already know it. Its reporting section needs two things settled before the
  project actively invites outside contributors: a dedicated project contact
  alias (rather than the maintainer's everyday personal email, for portability and light
  privacy separation) and an identified secondary/backup contact who isn't the primary
  maintainer, specifically so a report *about* the maintainer has a safe channel — the
  template alone doesn't solve this for a genuinely solo project.
- **Commit conventions**: free-form while solo, by deliberate choice. The switch to
  Conventional Commits (`feat:`/`fix:`/`chore:`/etc., enabling automated `CHANGELOG.md`
  generation via a tool like `git-cliff`) is deferred, but gated on the same milestone as
  the community files above: **before the project starts being discussed with other
  people.** Retrofitting a commit convention partway through leaves a gap in generated
  history, so this is a "do it right before it matters" decision rather than "do it
  whenever."

## 14. Open / Deferred Items

These were deliberately deferred during discussion rather than decided now. This list is
the durable record — earlier in this project's discussion phase these were tracked in an
in-session task tool, which turned out not to persist reliably across sessions, so this
document (not that tool) is the canonical source going forward.

1. **Evaluate the `ssi` crate more deeply** during JSON-LD/Data Integrity implementation —
   is any part of it worth depending on, versus the default plan of implementing
   domain-specific format/spec logic in-house (§5's dependency policy)?
2. **VC-API vector-consumption spike**: build two throwaway branches when implementing
   JSON-LD/Data Integrity — (a) extract W3C VC-API-shaped test vectors and adapt them into
   direct calls against `vcrd-core`, versus (b) a minimal local VC-API HTTP shim so the
   official test harness runs unmodified. Compare the actual working code and the delta
   from `main` on each, then merge the winner and discard the other.
3. **Set up `cargo-fuzz` targets** for `vcrd-core`'s untrusted-input parsers, seeded from
   the same vendored conformance fixtures used in testing (§10).
4. **Fable-based review of this document**, with particular attention to security risks —
   threat model completeness, verification-bypass classes, resource-exhaustion surface,
   crypto dependency choices, and any other design-level security gap, before
   implementation starts in earnest.
5. **Research non-flaky test patterns** for `vcrd --version --verbose`-style output, once
   that feature is actually built — naive tests would be coupled to the exact build
   environment/commit/timestamp.
6. **Switch to Conventional Commits and add `CHANGELOG.md`**, gated on "before talking to
   other people about the project" (§13).
7. **Wire up `cargo-semver-checks`** in CI before the 1.0 release (§12).
8. **Add `CONTRIBUTING.md`, issue/PR templates, and `CODE_OF_CONDUCT.md`** to the repo,
   same gating milestone as item 6 (§13).
9. **Enable GitHub's "require approval for first-time contributor workflows" setting** —
   an early-setup item, not gated on going public, since it costs nothing while solo
   (§11).
10. **Add a `CODEOWNERS` entry for `.github/workflows/*`** — same early-setup timing as
    item 9 (§11).
11. **Design `vcrd-core`'s diagnostic/build-info API**, with `vcrd-cli`'s
    `--version --verbose` as one consumer of it rather than a CLI-only feature, and
    resolve the still-open scope question between ordinary bug-report-oriented output and
    a full dependency/SBOM-style manifest (§7).
12. **Identify a secondary Code of Conduct contact** — someone other than the primary
    maintainer — before actively inviting outside contributors (§13).
13. ~~Rename the GitHub repo and local clone from `vcrdtool` to `vcrd`~~ — **done**; the
    old repo was deleted and a new `vcrd` repo created directly.
14. **Set up `cargo-llvm-cov` coverage tracking** with the ratchet (not hard-gate) policy
    described in §10, and document that policy in `CONTRIBUTING.md`.

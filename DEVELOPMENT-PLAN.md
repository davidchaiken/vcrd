# vcrd Development Plan

The order of the work: milestones, what each delivers, its exit criteria, and which
ARCHITECTURE §10 items it closes. It says when something is built, not what it is —
[REQUIREMENTS.md](REQUIREMENTS.md) states what vcrd must do and
[ARCHITECTURE.md](ARCHITECTURE.md) how it is built (ARCHITECTURE §1). This document is
retired once its milestones are done; ARCHITECTURE §10 is the durable list of open items.

It began as a review of REQUIREMENTS.md and ARCHITECTURE.md at commit `a92209e` on branch
`spike/vc-jwt`, dated 2026-09-19, with
[prototype/PROTOTYPE-FINDINGS.md](prototype/PROTOTYPE-FINDINGS.md) on the same branch as
evidence ("finding *N*" below has ARCHITECTURE's meaning). The two findings that review
raised are now resolved in ARCHITECTURE: containment in §3, §4 and §6, and the decision
against `#[non_exhaustive]` on the result enums in §3.

Standards claims were checked against normative text, not memory. Two markers are used
throughout: **[verified]** means the sentence was read in the standard during that review;
**[inferred]** means it is reasoning from verified facts. The verification record at the
end says which texts were read directly, which came through a fetch tool's extraction, and
what was not verified.

## Milestones

**Approach (decided).** A thin end-to-end slice through the CLI first, bytes in to exit code
out, for one narrow case; then widen milestone by milestone. Trunk-based development
(REQUIREMENTS §13). Every milestone ends with the review REQUIREMENTS §11 prescribes: the
implementation against the normative text of every standard it implements, each gap a test
that cites the section, fails, is fixed, and passes. Where the review behind this plan already found a
normative sentence the design does not yet cover, it is listed under that milestone's review
as a known input, so the first review starts with a queue rather than a blank page. Tags
refer to ARCHITECTURE §10. Milestone sizes are unequal: milestones 1 and 5 are the large ones.

| Milestone | Delivers | Closes |
|---|---|---|
| 0 Skeleton | buildable workspace, CI, repository hardening | [P3] [P4] |
| 1 Thin slice | `vcrd inspect`/`verify` on a VC-JOSE-COSE credential, Ed25519, `did:key` | [S3] [S4] [S5] [S6] [S7] [G1] |
| 2 Keys and algorithms | five algorithms, caller keys, embedded-key precedence, allowlist, full provenance | [S1] [S2] [C1] [C2] [C3] [Q4] |
| 3 CLI contract | config file, env, designations, `formats`/`suites`, man pages, fuzz, coverage, limits corpus | [Q2] [T2] [T5] [T6] |
| 4 Presentations | `vp+jwt` with enveloped credentials, challenge/domain | — |
| 5 Data Integrity | `eddsa-rdfc-2022`, `eddsa-jcs-2022`, pinned contexts, canonicalization budget | [Q1] [T1] |
| 6 Release 0.1.0 | community files, semver-checks, differential harness, distribution | [P1] [P2] [P5] [P6] [T4] [T7] [D1] [D2] |

### Milestone 0. Repository skeleton

**Scope.** Cargo workspace per REQUIREMENTS §7: resolver 3, edition 2024,
`[workspace.package]` inheritance, `license = "MIT OR Apache-2.0"` (§5); `vcrd-core` and
`vcrd-cli`; workspace clippy lints denying `unwrap_used`, `expect_used` and
`indexing_slicing` outside tests; `#![forbid(unsafe_code)]` in both crates; features
`std-clock` and the first format feature, `vc-jose`; `compile_error!` in `vcrd-cli` with no
format (ARCHITECTURE §2). CI per REQUIREMENTS §13: Linux and macOS, the pinned MSRV
toolchain plus a non-blocking latest-stable job, `fmt`, `clippy`, `test`, and the feature
matrix (core with every combination of its features, CLI default, and CLI with no format,
which must fail to build). Supply chain per REQUIREMENTS §12: `cargo-deny`, `cargo-audit`,
committed `Cargo.lock`, no `pull_request_target` trigger, a read-only token, SHA-pinned
actions with Dependabot, `SECURITY.md`, [P3] and [P4].

**Delivers.** `vcrd --help` and `vcrd --version` build on both platforms;
`cargo test --workspace` green with no tests; `cargo clippy --all-targets` clean, with the
lint confirmed to fire by the prototype's method (add an `unwrap()`, watch it fail).

**Exit criteria.** CI green on every matrix cell. The lint-fires check recorded as a CI
step rather than a memory.

**Closes.** [P3], [P4].

**Review.** No standard is implemented. Review against REQUIREMENTS §7, §12's CI list and
§13's matrix, sentence by sentence.

### Milestone 1. Thin slice: one VC-JOSE-COSE credential, Ed25519, `did:key`

The first format is VC-JOSE-COSE over a VCDM 2.0 payload in JWS compact serialization, as
the prototype decided (finding 7). REQUIREMENTS §10 leaves the exact JWT-based format to
implementation time; ARCHITECTURE §10's [S3]–[S7] already assume this one, and VC-JOSE-COSE
§3.1.1 makes compact serialization the one a verifier MUST support **[verified]**. Ed25519
first because `did:key` with the `ed25519-pub` codec is the smallest self-contained key
route, the prototype's canonical example is Ed25519, and one algorithm is enough to make
every other `alg` exercise the by-name rejection path from day one.

**Include.**

- *Input.* One file path or stdin. Compact JWS only.
- *Parse.* Size cap on the encoded input, segment split, strict base64url (RFC 7515 §5.2
  steps 2, 6 and 7 forbid line breaks and extra characters **[verified]**), depth cap by a
  string-aware byte prescan before `serde_json` (ARCHITECTURE §4), `alg` present, `crit`
  handling (below), an embedded `jwk` parsed into a typed JWK (ARCHITECTURE §3), the
  registry with `No`/`Maybe`/`Yes` detection, and `Report.contained` (ARCHITECTURE §3),
  empty at this milestone.
- *Inspect.* VCDM 2.0 §4.3 (`@context` first item; subsequent items URLs or objects),
  §4.5 (`type` present; `VerifiableCredential` per the table of objects that MUST have a
  type), §4.7 (issuer present; a URL or an object with an `id` URL), §4.8
  (`credentialSubject` present; each object the subject of at least one claim), §4.9
  (`dateTimeStamp` values; `validUntil` not earlier than `validFrom`; currency against
  the injected clock and skew). VC-JOSE-COSE §3.1.1 `typ` SHOULD be `vc+jwt` and `cty`
  SHOULD be `vc` (warnings); §3.1.3 `vc`/`vp` MUST NOT be present (error; the VCDM 1.1
  mapping detected, named, attributed to vcrd, exit 6, as in finding 7); §4.1.2 `iss`, if
  present, MUST match `issuer` or `issuer.id` (error); `jti`/`id` and
  `sub`/`credentialSubject.id` SHOULD agree (warnings). All **[verified]**.
- *Verify.* EdDSA/Ed25519 via `verify_strict`, `is_weak` at resolution (ARCHITECTURE §8);
  `none` rejected; every other `alg` unsupported by name (attribution vcrd, exit 6). Key
  resolution from the credential's `issuer` (the VCDM-normative identifier; `iss` is a
  JWT convenience checked at inspect) when it is a `did:key` with codec `0xed`; other
  codecs named and attributed to vcrd; an embedded `jwk` refused with its own finding
  (REQUIREMENTS §10, rule 5); `kid` checked against `<did>#<multibase>` (below);
  provenance `source: issuer_identifier` with thumbprint. The signature's own currency:
  `exp` and `iat` in the verify phase (below), which means `VerifyOutput` carries a
  securing-mechanism validity status and the suite consults the clock, extending
  ARCHITECTURE §4's table.
- *Features.* A Cargo feature for the first proof suite, EdDSA over JWS, beside
  `vc-jose` (ARCHITECTURE §2: one feature per format and per proof suite), its name
  decided at implementation. `vcrd-cli` forwards it, and `scripts/feature-matrix.sh` adds
  it, building `vcrd-core` in every combination of its three features (REQUIREMENTS §13).
  Decide whether `vcrd-cli` also refuses to build with no suite, as it does with no
  format: a binary that can parse and inspect but not verify still does part of its job.
- *Output.* The JSON envelope with every always-present key of ARCHITECTURE §6,
  `schema_version: 0`, `contained: []`; `text` via `tabled`; `plain`; every claim value
  masked by default; `--unsafe` with the stderr banner and the `reveals` list;
  `--format`, `--now`, a skew flag (zero default), `--verbosity` including 0; `NO_COLOR`;
  exit codes 0–6; `vcrd <file>` and piped input default to `inspect`. Caller faults are
  emitted as the one JSON document: parse arguments with `clap`'s fallible entry point,
  because `clap`'s own usage-error exit status collides with vcrd's code 2 (not verified
  that review; check `clap::Error::exit` at implementation).
- *Fixtures, negative first* (REQUIREMENTS §11): happy Ed25519; tampered signature;
  expired; not yet valid; `validUntil` before `validFrom`; `alg: none`; `alg: ES256`
  (unsupported by name in this slice); embedded `jwk` only (refused); `did:key` encoding
  the identity point (weak-key finding); small-order `R` under an ordinary key; the VCDM
  1.1 `vc` mapping; over the size cap; over the depth cap; JWS JSON serialization
  (rejected by name); unknown `crit` extension; `exp` in the past with `validUntil` in the
  future; `iss` disagreeing with `issuer`; missing `kid` with a `did:key` issuer.
- *Tests.* The canary redaction test across all three formats (ARCHITECTURE §7); CLI
  black-box tests with `assert_cmd` asserting finding code, attribution and exit code;
  core unit tests offline with the injected clock.
- *The one curated example* (REQUIREMENTS §11): a self-signed Ed25519 credential produced
  by the dev-only signing helper, committed as a static file, pointed at by the README.
- *[G1]* The debugging guide, executed end to end on this code: REQUIREMENTS §6 says an
  unrun procedure does not count as documented, and milestone 1 is the first time there is
  code to run it on.
- The result enums defined without `#[non_exhaustive]`, so that a later variant breaks
  the JSON mapping rather than falling through a wildcard arm (ARCHITECTURE §3).

**Exclude** (each has a later milestone): other algorithms; caller-supplied keys; the
embedded-key opt-in; the algorithm allowlist (meaningless with one algorithm; its `Context`
field and finding code are additive); the configuration file and environment variables;
per-path redaction designations and hashing; `vcrd formats`/`suites`; man pages and
completions; presentations; JSON-LD; network; SD-JWT; fuzzing; benchmarks; differential
testing; the diagnostic build-info API.

**Delivers.**

```bash
cargo test --workspace && ./target/debug/vcrd verify examples/ed25519.jwt --now 2026-10-01T00:00:00Z --format json
```

exits 0 and prints one JSON document; each negative fixture prints one JSON document and
exits with its documented code.

**Exit criteria.** Every fixture asserts a specific finding code, attribution and exit code,
never merely "some error". The canary test passes for `json`, `text` and `plain`. The
feature matrix and lints are clean. `Report.contained` and the envelope's `contained` key
exist. The milestone review is complete, with each gap below and any others found taken
through the red-then-green cycle.

**Closes.** [S3], [S4], [S5], [S6], [S7], [G1].

**Milestone review.** Texts: VCDM 2.0 §1.3, §2 (definitions), §4.3–4.9, §6.1, §7.1–7.2;
VC-JOSE-COSE §1.1, §3.1.1, §3.1.3, §4.1, §4.2, §5.1, §5.4; RFC 7515 §4, §4.1.x, §5.2, §7.1;
RFC 7519 §4.1, §7.2; RFC 8037 §2–3; RFC 8032 as the crate implements it. Known inputs, all
**[verified]** unless marked:

1. RFC 7515 §4.1.11: "If any of the listed extension Header Parameters are not understood
   and supported by the recipient, then the JWS is invalid." Neither document mentions
   `crit`. Also RFC 7515 §4: duplicate header names MUST be rejected, or the parser MUST
   return the lexically last; `serde_json`'s behavior must be stated and tested.
2. RFC 7519 §4.1.4: an expired `exp` means the JWT "MUST NOT be accepted for processing";
   VC-JOSE-COSE §3.1.3 says registered claims "are to be interpreted as defined by the
   specifications referenced in the registries" and that `iat`/`exp` "represent the
   issuance and expiration time of the signature". So [S6] closes as an error-severity
   verify finding, not a warning, and `nbf` (NOT RECOMMENDED there, RFC 7519 §4.1.5 if
   present) is handled the same way. Note that VC-JOSE-COSE §3.1.3 is headed "This section
   is non-normative" while containing MUST NOT and SHOULD sentences; the enforcement
   language comes from RFC 7519.
3. VC-JOSE-COSE §4.1.2 makes the `iss`/`issuer` pair a MUST, so that half of [S7] is error
   severity; the `jti`/`id` and `sub`/`credentialSubject.id` halves stay SHOULD (§3.1.3).
4. VC-JOSE-COSE §4.1.1: "kid MUST be present when the key of the issuer or subject is
   expressed as a DID URL"; §4.2: with `iss` absent and the issuer a URL, "the kid MUST be
   an absolute [URL] to a verification method". The did:key method forms that identifier
   as `<did>#<multibaseValue>` (did:key v0.9 create algorithm, via the fetch tool's
   extraction). ARCHITECTURE §8 resolves from the identifier alone and says nothing about
   `kid`; a missing or foreign `kid` is a conformance finding but does not change which
   key is used.
5. VCDM 2.0 §4.9: values MUST be XML Schema 1.1 `dateTimeStamp`; ARCHITECTURE §2 uses the
   `time` crate's RFC 3339 parser. Enumerate the lexical differences (case of `T`/`Z`,
   years outside 0001–9999, hour 24) and decide; a test per difference.
6. VCDM 2.0 §4.8: "each object MUST be the subject of one or more claims", so [S5]'s fix is
   a distinct "empty subject" finding, not a corrected "missing" one.
7. VCDM 2.0 §1.3: a conforming verifier "MUST produce errors when non-conforming documents
   are detected" and §7.1's algorithm sets `status` false when the document is
   non-conforming. Document the mapping from `Report` to §7.1's result: `status` is
   inspect passed and verify passed, so the review can assert vcrd "returns errors for
   the same invalid inputs" (§7.1's allowance for different ordering and error types).
8. VCDM 2.0 §2 defines verification as including "if present, the status check succeeds".
   vcrd's `verify` does not check status offline, so a credential with `credentialStatus`
   must list status under `not_evaluated`, and the glossary entry for *Verify*
   (REQUIREMENTS §15) should say so at the terminology check.
9. VC-JOSE-COSE §3.1.1: JSON serialization is NOT RECOMMENDED and compact is MUST; an input
   in JSON serialization fails detection by name, attributed to vcrd, rather than as "no
   format matched".

### Milestone 2. Key material and the algorithm table

**Scope.** ES256, ES512, RS256, HS256 as prototyped (finding 5); a recorded decision on
ES384, ES256K and the PS and RS384/RS512 families ([C3]), implementing what is decided. A
caller-supplied JWK set (flag name is implementation-time), matched by `kid` else the sole
key. The full precedence of REQUIREMENTS §10 with RFC 7638 thumbprint matching, the
embedded-key opt-in, and the `credential_key` block with `matched` and `verifies_signature`
(ARCHITECTURE §8). The algorithm allowlist as a `Context` input and a CLI flag; policy
rejection (exit 5) distinct from unsupported (exit 6), both reported when both apply.
Binding of each algorithm to key type *and curve*. Weak-key criteria at resolution: RSA
modulus of at least 2048 bits (RFC 7518 §3.3 **[verified]**), HS256 key of at least 256
bits (RFC 7518 §3.2 **[verified]**), the EC identity point, Ed25519 `is_weak`. [Q4].
`did:key` decoding for `p256-pub` and `p521-pub`; `p384-pub`, `secp256k1-pub` and
`rsa-pub` named only. [C1] the audit-status table; [C2] the elliptic-curve crate
generation.

**Delivers.** `vcrd verify` for five algorithms, with caller keys, the embedded-key opt-in
and the allowlist; provenance for every row of ARCHITECTURE §8's situation table.

**Exit criteria.** Fixtures: algorithm confusion (HS256 with the issuer's public-key bytes
as secret, reported as key-type mismatch, not as unsupported); `none`; unsupported
(ES256K); policy-rejected; unsupported and policy-rejected at once (exit 6, two findings);
key substitution (`matched: false`, `verifies_signature: true`, exit 4); embedded-only
refused, and accepted with the opt-in (exit 0, `source: credential_embedded`); RSA 1024
and HS256 128-bit keys (weak-key findings); a P-384 `did:key` (named, exit 6); ES512
happy path, the EUDI evidence point of REQUIREMENTS §10.

**Closes.** [S1], [S2], [C1], [C2], [C3] (decision recorded; anything left out is a named
follow-on), [Q4].

**Milestone review.** Texts: RFC 7518 §3.1–3.6, including §3.4's `R || S` encoding at 64,
96 and 132 octets **[verified]** and §3.6's "MUST NOT accept Unsecured JWSs by default"
**[verified]**; RFC 7517; RFC 7638; RFC 8037; did:key v0.9 create and read algorithms;
VC-JOSE-COSE §4.1–4.2 and §5's "verifiers SHOULD strive to minimize the processing of
untrusted data" during key discovery **[verified]**. Known inputs: the did:key v0.9 table,
as extracted by the fetch tool, lists codecs `0xe7`, `0xec`, `0xed`, `0x1200` and `0x1201`
only; `p521-pub` (`0x1202`) and `rsa-pub` (`0x1205`) come from the multicodec registry,
which that review did not read. Record the source for each codec when it is implemented,
and treat P-521 `did:key` as an extension beyond the method spec's table.

### Milestone 3. The CLI contract, configuration and hardening

**Scope.** The configuration file (TOML in the per-OS directory) and environment variables,
with the precedence flag > env > config > default resolved per path for designations
(REQUIREMENTS §8). Per-path show/hash/mask designations with the `reveals` list; an initial
hash construction chosen and labelled provisional (REQUIREMENTS §16 item 18 stays open).
`vcrd formats` and `vcrd suites`. Man pages and completions from `clap`. [Q2] decided.
Stderr diagnostics per verbosity level. [T2] `cargo-fuzz` targets for the JWS parser and
the depth prescan, seeded from fixtures, in a workspace-excluded `fuzz/` on a nightly job.
[T5] coverage with the ratchet policy text ready for `CONTRIBUTING.md`. [T6] structural
limits derived from a corpus nobody on the project wrote: the W3C VC test-suite fixtures,
VC-JOSE-COSE §8's examples, and outputs of the oracles REQUIREMENTS §11 names, each with
source and license tracked. Property tests: base64url and JWS split/join round trips, and
the depth prescan agreeing with `serde_json`'s rejection at 128. The performance tripwire
and a `criterion` baseline (REQUIREMENTS §11).

**Delivers.** `vcrd` usable unattended by a CI job or agent with a config file and no
flags; the same result whether a setting came from a flag, the environment or the file.

**Exit criteria.** Black-box tests for every precedence combination; the canary test
extended to designations and hashing; fuzz targets run for a fixed budget in CI without a
panic; limit defaults documented with the measuring command and the corpus.

**Closes.** [Q2], [T2], [T5], [T6].

**Milestone review.** No new standard. Review the CLI against REQUIREMENTS §8 and §9
sentence by sentence, each requirement a black-box test. Re-run milestones 1 and 2's review
lists over the corpus: a corpus credential that fails inspect is either a real
non-conformance or a vcrd bug, and the review records which.

### Milestone 4. Presentations for VC-JOSE-COSE

**Scope.** `vp+jwt` per VC-JOSE-COSE §3.1.2. `Document.kind = presentation` and `holder`.
`EnvelopedVerifiableCredential`: decode the `data:` URL (RFC 2397, base64 or
percent-encoded), take its media type as a detection hint, and hand each contained input
to the phase runner, which recurses through the registry (ARCHITECTURE §4).
`EnvelopedVerifiablePresentation`
nesting under the `Limits` caps. The holder proof: the presentation JWS verified against
the holder's key from `holder` as a `did:key`, from `cnf` (VC-JOSE-COSE §4.1.3, RECOMMENDED
**[verified]**), or from caller-supplied material. VCDM 2.0 §4.13's rule that a
presentation with a self-asserted credential secured only by the presentation's mechanism
MUST include `holder` **[verified]**. The expected challenge and domain: VC-JOSE-COSE
contains no sentence about nonce, audience, challenge or domain **[verified: none found]**,
so for JOSE presentations the binding claims are a protocol convention; adopt OpenID4VP's
`nonce` and `aud`, say so in the finding, and with no parameters supplied report
`not_evaluated: replay binding` (REQUIREMENTS §10). Exit code and `status` aggregated over
the tree (ARCHITECTURE §6). The text renderer for a tree: one block per contained report.

**Delivers.** `vcrd verify presentation.jwt` with expected-nonce and expected-audience
flags (names implementation-time), reporting the holder proof and each contained
credential separately.

**Exit criteria.** Fixtures: a presentation with two enveloped credentials, one expired
(exit 3; presentation verify passed; credential 1 passed; credential 2 inspect failed); a
presentation enveloping an `application/vc+sd-jwt` credential (contained parse fails,
named by media type, attributed to vcrd); wrong nonce (holder proof fails replay binding);
no parameters (`not_evaluated`); nesting over the cap; a self-asserted credential without
`holder`.

**Closes.** No §10 tag; implements the containment design (ARCHITECTURE §3, §4, §6).

**Milestone review.** Texts: VCDM 2.0 §4.13 (each MUST for enveloped credentials and
presentations), VC-JOSE-COSE
§3.1.2, §4.1.3 and §5.4 ("All claims expected for the typ MUST be present"
**[verified]**), RFC 2397, RFC 7519 §4.1.3 (`aud`: "Each principal intended to process the
JWT MUST identify itself with a value in the audience claim" **[verified]**).

### Milestone 5. JSON-LD with Data Integrity

**Gating decision, before the milestone starts.** ARCHITECTURE §2 lists dependencies for the
JOSE path only, and [Q1] covers the `ProofInput` boundary only; the components that
dominate this milestone's cost are not yet decided. Apply REQUIREMENTS §6's case-by-case rule
for domain-specific spec logic and record the result in ARCHITECTURE §2 and §10:

- JSON-LD 1.1 expansion and deserialization to RDF, which `eddsa-rdfc-2022` requires:
  "converting unsecuredDocument to RDF statements, applying the RDF Dataset
  Canonicalization Algorithm to the result" (EdDSA cryptosuites §3.2.3 **[verified]**).
  A pure-Rust processor exists; writing one from the JSON-LD API spec is work of the same
  order as the rest of vcrd **[inferred]**.
- RDFC-1.0 with the fail-closed permutation budget REQUIREMENTS §6 requires. Whichever
  implementation is chosen, in-house or a crate, must expose that budget; check before
  choosing.
- JCS (RFC 8785) for `eddsa-jcs-2022` (§3.3.3 **[verified]**), small enough to write.
- A context loader trait with a pinned cache, implementing Data Integrity §4.6:
  "Applications MUST use the algorithm in Section 4.6 Context Validation, or one that
  achieves equivalent protections" **[verified]**, and REQUIREMENTS §12's loud
  unpinned-context finding.

**Scope.** Feature `jsonld`. The JSON-LD credential format (embedded `proof`); suites
`eddsa-rdfc-2022` and `eddsa-jcs-2022` with the hash order proof-configuration hash then
document hash (§3.2.4, §3.3.4 **[verified]**) and `eddsa-jcs-2022`'s check that the
document's `@context` starts with the proof options' `@context` (§3.3.2 **[verified]**).
`ProofInput::DataIntegrity { unsecured document, proof options }` ([Q1]). `Multikey`
verification methods and the `did:key` DID document with `<did>#<multibase>`.
`verificationMethod` as a key hint. Data Integrity §4.4 steps 2–7 **[verified]**: a missing
`proof` map, or a proof without `type`, `verificationMethod` or `proofPurpose`, is the
first real "impossible" case of REQUIREMENTS §4's blocking rule, which settles the report
structure REQUIREMENTS §16 item 20 leaves open; `expectedProofPurpose` joins `Context`
(`assertionMethod` for credentials, `authentication` for presentations). Proof sets
(§2.1.1); proof chains as a follow-on. The canonicalization budget as a verify-phase
bounded-out finding attributed to vcrd; note that REQUIREMENTS §4's "dangerous, internal"
block requires *inspect* to predict the cost, so either a cheap predictor (blank-node
count over a threshold) is added at inspect or the budget itself is the control, and the
choice is written down. Vendored vectors with source and license: the RDFC-1.0 test suite,
EdDSA cryptosuites Appendix B, VC test-suite fixtures. [T1] the two-branch VC-API spike.
Data Integrity presentations as the per-format follow-on PR: §4.4 steps 6 and 7 map
directly onto REQUIREMENTS §10's expected domain and challenge **[verified]**.

**Delivers.** `vcrd verify credential.jsonld` for both cryptosuites, offline, against
`did:key` and caller-supplied keys; an unpinned or inline `@context` reported at error
severity with the prominence REQUIREMENTS §12 demands.

**Exit criteria.** RDFC-1.0 vectors pass; Appendix B vectors verify; a poison-graph fixture
trips the budget and fails closed; the feature matrix includes `jsonld` alone and with
`vc-jose`; the review is complete.

**Closes.** [Q1], [T1]; provides the first case for REQUIREMENTS §16 item 20.

**Milestone review.** Texts: Data Integrity 1.0 §2.1–2.4, §4.4–4.7; EdDSA cryptosuites §2,
§3.2, §3.3, §4.1 (Ed25519 security properties, cross-checked against the `verify_strict`
decision); RDFC-1.0; RFC 8785; JSON-LD 1.1 and its API (expansion, to-RDF); Controlled
Identifiers 1.0 (Multikey); VCDM 2.0 §5.13 and §6.1 ("JSON-LD compacted document form MUST
be used" **[verified]**).

### Milestone 6. First release, 0.1.0

**Scope.** [P6] first: the move to a GitHub organization, with CODEOWNERS naming its
maintainers team, since Trusted Publishing and the release URLs below name the repository's
owner. [P1] Conventional Commits and a generated `CHANGELOG.md`; [P2]
`CONTRIBUTING.md` (build and test commands, the trait on-ramp, the coverage policy, the
versioning-split intent of REQUIREMENTS §7, the debugging guide), issue and PR templates,
`CODE_OF_CONDUCT.md` with a project contact alias and [P5]. [T4] `cargo-semver-checks`,
cheap to wire now. [T7] the differential harness: a workspace-excluded tool crate that
runs vcrd and one oracle over the curated examples and the corpus, compares the
(parse, inspect, verify) verdict tuple, and stores each disagreement as a fixture; the
first oracle as a dev-dependency, which REQUIREMENTS §6 permits, with the protocol-level
services of REQUIREMENTS §11 later. [D1], [D2]. The threat model promoted to
`docs/threat-model.md` (REQUIREMENTS §12). README quickstart pointing at `examples/`.
`cargo-dist` binaries, crates.io through Trusted Publishing, `Cargo.lock` tagged.
`schema_version` stays 0 at 0.1.0 and is declared 1 in a later 0.x once external
consumers have used it (REQUIREMENTS §9).

**Delivers.** Installable `vcrd-cli` and prebuilt binaries; `vcrd-core` on docs.rs.

**Exit criteria.** The release pipeline runs from a tag; a semver-checks baseline exists;
the changelog is generated; every §10 item is closed or carried with its tag.

**Closes.** [P1], [P2], [P5], [P6], [T4], [T7], [D1], [D2].

**Milestone review.** Re-run every prior milestone's review list against the release
candidate, since REQUIREMENTS §11's practice is cumulative, and run the terminology check
of REQUIREMENTS §15 over every standard now in scope.

## Deferred past the first release

- **SD-JWT VC** (REQUIREMENTS §10's near-term roadmap): [Q3] first, since a withheld claim
  is neither present nor absent in `Document`; `cnf` holder binding.
- **Network:** `did:web`, status lists, the hardening bar of REQUIREMENTS §12, the first
  "dangerous, external" instance of the blocking rule (`jku`, `x5u`, private-address
  resolution). VC-JOSE-COSE §4.2's requirement that a controlled identifier document's
  verification method be a `JsonWebKey` with `publicKeyJwk` **[verified]** becomes live
  here.
- **The live verifier** and OpenID4VP (REQUIREMENTS §16 items 13–15); **mdoc**;
  **AnonCreds/BBS+**; **WASM/browser**.
- **The diagnostic build-info API** (REQUIREMENTS §16 item 10) and [T3]; plain `--version`
  ships in 0.1.0.
- **[Q5]**, revisiting `#[non_exhaustive]` on the result enums, which only bites once a
  breaking change is expensive, and **[Q6]**, typed finding detail for an implementation
  outside this repository, which waits for the first such implementation.
- Proof chains; any algorithm deferred in milestone 2; Windows CI; SBOM and reproducible
  builds; a CI differential job beyond the local harness; registration against the W3C
  test suites (REQUIREMENTS §14).

## Verification record

Read directly from a local text conversion of the published page (fetched 2026-09-19):
VCDM 2.0 §2, §4.4, §4.5, §4.7–4.9, §4.13, §6.1–6.3, §7.1–7.2; VC-JOSE-COSE §3.1.3, §4, §5.

Read through the fetch tool's extraction, which paraphrases around the quoted sentences:
VCDM 2.0 §1.3, §4.3; VC-JOSE-COSE §3.1.1–3.1.2; Data Integrity 1.0 §2.1, §2.2, §4.4, §4.6;
EdDSA cryptosuites §3.2.3–3.2.4, §3.3.2–3.3.4; RFC 7515 §4, §4.1.2–4.1.5, §4.1.11, §5.2;
RFC 7518 §3.1–3.4, §3.6; RFC 7519 §4.1.1, §4.1.3–4.1.6, §7.2; did:key v0.9 (format, create
algorithm, key table); the Rust Reference on `non_exhaustive`.

Claims checked and found consistent with the text (so not reported): [S1]–[S5] as cited;
[S6] and [S7] as cited, with the severity corrections in milestone 1's review list;
ARCHITECTURE §5's citation of EdDSA cryptosuites §3.2.3 and §3.3.3 and finding 4's hash
order; ARCHITECTURE §8's `none` rule against RFC 7518 §3.6; RFC 7515 §4.1.2 and §4.1.5 as
cited for `jku` and `x5u`; REQUIREMENTS §15's reading of VCDM 2.0 §2's *verification* and
*validation*; the phase model's compatibility with VCDM 2.0 §7.1.

Not verified by that review: the multicodec registry values `0x1202` and `0x1205`; RFC 7638;
RFC 8785; the behavior of any crate named in ARCHITECTURE §2; `clap`'s usage-error exit
status. Rework-cost and effort statements in this plan are inferred.

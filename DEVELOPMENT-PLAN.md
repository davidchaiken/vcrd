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
| 2 Keys and algorithms | RFC 7518's signature algorithms, caller keys, embedded-key precedence, allowlist, full provenance, Linux debugging | [S1] [S2] [C1] [C2] [C3] [Q4] [G2] |
| 3 CLI contract | config file, env, designations, `formats`/`suites`, man pages, fuzz, coverage, limits corpus, a VCDM 2.0 §7.1 result | [Q2] [Q7] [T2] [T5] [T6] |
| 4 Presentations | `vp+jwt` with enveloped credentials, challenge/domain; JWS JSON serialization | [F1] |
| 5 Data Integrity | `eddsa-rdfc-2022`, `eddsa-jcs-2022`, pinned contexts, canonicalization budget, VCDM 1.1's JWT encoding | [Q1] [T1] [F2] |
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
  empty at this milestone. Decided 2026-09-24: parse reports what it finds without
  stopping later phases wherever the input can still be read. Duplicate member names
  keep the lexically last value and are recorded, and inspect reports each as an error
  (exit 3) while verify still runs (known input 1). A malformed `crit` is an inspect
  error attributed to the input (exit 3); a well-formed `crit` naming an extension vcrd
  does not implement fails verify, named and attributed to vcrd (exit 6). Decided
  2026-09-29: an input over a structural limit is attributed to caller policy (exit 5);
  trailing ASCII whitespace is ignored and reported for information; the CLI reads at
  most one byte past the size limit (ARCHITECTURE §4).
- *Inspect.* VCDM 2.0 §4.3 (`@context` first item; subsequent items URLs or objects),
  §4.5 (`type` present; `VerifiableCredential` per the table of objects that MUST have a
  type), §4.7 (issuer present; a URL or an object with an `id` URL), §4.8
  (`credentialSubject` present; each object the subject of at least one claim), §4.9
  (`dateTimeStamp` values; `validUntil` not earlier than `validFrom`; currency against
  the injected clock and skew). VC-JOSE-COSE §3.1.1 `typ` SHOULD be `vc+jwt` and `cty`
  SHOULD be `vc` (warnings); §3.1.3 `vc`/`vp` MUST NOT be present (error; the VCDM 1.1
  mapping detected, named, attributed to vcrd, exit 6, as in finding 7); §4.1.2 `iss`, if
  present, MUST match `issuer` or `issuer.id` (error); `jti`/`id` and
  `sub`/`credentialSubject.id` SHOULD agree (warnings). All **[verified]**. `kid` checked
  against `<did>#<multibase>` here, not in verify: it is a conformance check, so a
  missing or foreign `kid` fails inspect (exit 3) while verify reports the signature
  (decided 2026-09-24; known input 4). Decided 2026-10-01:
  - URLs follow the WHATWG URL Standard, through the `url` crate; a URL the parser had
    to correct is a warning, one it cannot parse an error. Validity bounds follow XML
    Schema's `dateTimeStamp` where it differs from RFC 3339 (ARCHITECTURE §4), with a
    finding that marks values RFC 3339 accepts, so that the rule can be revisited if
    they occur in practice.
  - A subject with only an `id` is a warning; an empty subject, or an empty set of
    subjects, is an error ([S5]).
  - A missing or malformed `issuer` blocks verify as impossible, and the block names
    what is missing (`key_material`) and where vcrd looked (`consulted`); a parse
    failure's block names only the parse phase (REQUIREMENTS §16 item 20;
    docs/output.md). A URL issuer vcrd cannot resolve does not block. Decided
    2026-10-21, after review: a parse block no longer names a missing `document`, which
    described vcrd's internals rather than what the reader needs, that parse failed;
    `text` and `plain` say "parse failed" and "no key for verify".
  - VCDM 1.1's JWT encoding (`vc` or `vp` with no VCDM 2.0 `@context`) is named and
    attributed to vcrd, blocks verify, and skips VCDM 2.0's checks; reading it is
    ARCHITECTURE §10 [F2], in milestone 5. `vc` or `vp` beside a VCDM 2.0 payload is the
    input's error.
  - `kid` follows VC-JOSE-COSE §4.1.1 and §4.2 as written: a relative `kid` is an error
    when `iss` is absent, and is resolved against the issuer when `iss` is present. The
    JWK Thumbprint recommendation is a warning, for issuers whose URL is not a DID.
  - `not_evaluated` lists context resolution for every VC-JOSE-COSE credential, and
    status and schema when present, each as `not_implemented`.
  - Decided 2026-10-22, in the milestone review (docs/reviews/milestone-1.md, round 1):
    a registered header member whose value has the wrong JSON type is
    `inspect.header_member_type`, not reported as absent, and an `alg` that is not a
    string is `verify.algorithm_invalid`. An `aud` adds `audience` to `not_evaluated`,
    as `no_parameters_supplied`, until milestone 4 gives vcrd an expected audience.
    Naming nested JWTs and JWEs is ARCHITECTURE §10 [F3], with no milestone yet.
  - Decided 2026-10-23, in the milestone review (round 3, VC-JOSE-COSE): a registered
    claim of the wrong JSON type (`iss`, `sub`, `jti`, `aud`, and a header `iss`) is
    `inspect.jwt_claim_type`, and is not compared; a claim replicated in the header that
    differs from the payload's is `inspect.replicated_claim_mismatch`, a warning
    (RFC 7519 §5.3); `cnf` adds `holder_binding` to `not_evaluated`, `not_implemented`;
    and a presentation, by its `type`, is `inspect.presentation_unsupported`, attributed
    to vcrd, with `credential.kind: presentation`, its header checked against `vp+jwt`
    and `vp`, and verify blocked.
  - Decided 2026-10-24, in the milestone review (round 4, VCDM 2.0): a JSON credential
    or presentation that no format reads is `parse.data_integrity_unsupported`,
    attributed to vcrd, when it carries a `proof`, and `parse.not_secured`, attributed to
    the input, when it does not; the `id` of status, schema, terms-of-use, evidence and
    refresh-service objects is checked as a URL, and a schema without one is
    `inspect.id_missing`; `name` and `description` that are not strings or language value
    objects are `inspect.language_value_invalid`, a warning; `issuer_accreditation` is
    `not_implemented` until the trust anchor input of REQUIREMENTS §16 item 14 exists;
    and a result conforming to VCDM 2.0 §7.1 is ARCHITECTURE §10 [Q7], in milestone 3.
- *Verify.* EdDSA/Ed25519 via `verify_strict`, `is_weak` at resolution (ARCHITECTURE §8);
  `none` rejected; every other `alg` unsupported by name (attribution vcrd, exit 6). Key
  resolution from the credential's `issuer` (the VCDM-normative identifier; `iss` is a
  JWT convenience checked at inspect) when it is a `did:key` with codec `0xed`; other
  codecs named and attributed to vcrd; an embedded `jwk` refused with its own finding
  (REQUIREMENTS §10, rule 5);
  provenance `source: issuer_identifier` with thumbprint. The signature's own currency:
  `exp` and `iat` in the verify phase (below). Decided 2026-10-05:
  - The format reads `nbf`, `exp` and `iat` into the proof descriptor, the runner
    compares them with the clock, and each `ProofResult` carries its own validity
    (ARCHITECTURE §4's table). `exp` and `nbf` are errors (RFC 7519 §4.1.4–4.1.5);
    `iat` after the clock is a warning, since §4.1.6 sets no rule for it. A value that is
    not a number is an inspect error.
  - A small-order R is named, `verify.signature_small_order`, by checking R with
    `curve25519-dalek` before `verify_strict`, which rejects it without saying why.
  - A credential that carries a key is not blocked for want of an issuer: verify runs
    and refuses the key, attributed to caller policy (exit 5). An embedded key unlike
    the issuer key is a warning. Inspect reports a `jwk` it cannot read, one with
    private-key members, and an unknown key type (a warning attributed to vcrd).
  - A critical extension the suite does not implement fails verify, attributed to vcrd.
    The signature is still checked, and its outcome reported (decided 2026-10-07).
  - Decided 2026-10-23, in the milestone review (docs/reviews/milestone-1.md, round 2):
    `alg: "Ed25519"`, RFC 9864's fully specified name, is verified as `EdDSA` with an
    Ed25519 key is. `EdDSA`, which RFC 9864 deprecates, is `verify.algorithm_deprecated`,
    `info`, attributed to the input, and always in JSON. At level 1, `text` and `plain`
    leave out every `info` finding and count them; level 2 lists them. An Ed25519 key
    not encoded as RFC 8032 §5.1.3 requires is `did_key_undecodable`,
    `point_not_canonical` (in an embedded `jwk`, `inspect.jwk_invalid`); a component before
    the multibase value is `version_present`. An S not less than the group order is
    `verify.signature_scalar_out_of_range`, checked by vcrd. An X25519 or X448 `did:key`
    is `verify.did_key_not_for_signing`, attributed to the input; `ed448-pub` is named.
- *Features.* A Cargo feature for the first proof suite, EdDSA over JWS, beside
  `vc-jose` (ARCHITECTURE §2: one feature per format and per proof suite).
  `vcrd-cli` forwards it, and `scripts/feature-matrix.sh` builds it (REQUIREMENTS §13).
  Decided 2026-09-24: the feature is `jws`, one suite whose algorithm table milestone 2
  extends; and `vcrd-cli` refuses to build with no suite, as with no format, which the
  feature matrix checks. Decided 2026-09-27: CI builds the supported feature builds of
  ARCHITECTURE §2 on every change, through cargo-hack, and every combination weekly.
  Decided 2026-10-07: every combination runs on every change too, and a merge waits for
  it; `make ci-ok` still runs only the supported builds.
- *Output.* The JSON envelope with every always-present key of ARCHITECTURE §6,
  `schema_version: 0`, `contained: []`; `text` via `tabled`; `plain`; every claim value
  masked by default; `--unsafe` with the stderr banner and the `reveals` list;
  `--format`, `--now`, a skew flag (zero default), `--verbosity` including 0; `NO_COLOR`;
  exit codes 0–6; `vcrd <file>` and piped input default to `inspect`. Caller errors are
  emitted as the one JSON document: parse arguments with `clap`'s fallible entry point,
  because `clap`'s own usage-error exit status collides with vcrd's code 2 (not verified
  that review; check `clap::Error::exit` at implementation). Decided 2026-10-08
  (docs/output.md documents the result):
  - `text` is the default format, whether or not stdout is a terminal. `text` is tables;
    `plain` is one `name: value` line per item, a finding on one line with its detail as
    `name=value` pairs (kept on trial). No color.
  - `--verbosity` never changes JSON; 0 prints nothing in any format. For `text` and
    `plain`: level 1 shows the status, the credential's kind, issuer, types, and validity
    with its bounds, the inspect and verify phases with `blocked_by`, each proof's
    outcome, own validity, key source and the key's thumbprint, the claims, the findings
    (from 2026-10-23, the `info` ones counted, not listed) and, last, `not_evaluated`;
    level 2 everything except `credential.metadata`, the header included;
    level 3 everything. Decided 2026-10-24, in the milestone review
    (docs/reviews/milestone-1.md): `text` gives the credential's validity, the key's
    source and the embedded key as phrases, where `plain` keeps the values; below the
    checks not evaluated, it names docs/findings.md's section "Checks not evaluated",
    which describes each check and reason.
  - Decided 2026-10-27, in the milestone review (docs/reviews/milestone-1.md, round 7):
    the terms of ARCHITECTURE §8's "Keys and proofs" (embedded key, issuer key,
    caller-supplied key, proof key, deciding proof key, refused), and its key and proof
    table, with a test of the ten rows milestone 1 produces. A proof's result is
    `correct`, `incorrect` or `not_attempted`. `key_provenance.embedded_key` replaces
    `credential_key`, with `same_as_issuer_key` (absent when there is no issuer key) and
    `proof`; `verify.embedded_key_mismatch` replaces `verify.credential_key_mismatch`,
    and `verify.embedded_key_proof_correct` names key substitution. At level 1, `text`
    says `Deciding proof key   issuer key, from did:key` and, for example,
    `Embedded key   header.jwk: a different key; proof correct`. A caller-supplied key
    must be the same key as the issuer key (REQUIREMENTS §10, amended); milestone 2
    implements it.
  - Every value carries its visibility, `non_sensitive`, `masked` or `revealed`: in JSON
    on each value, in a Visibility column in `text` and `plain` (decided 2026-10-21,
    after review, in place of an Unmasked column and JSON's `treatment`). JSON keeps
    `reveals`, each entry naming the key its path is relative to and its visibility,
    `revealed`; milestone 3's hashed designation adds `hashed`.
  - Each key is shown with its JWK beside its thumbprint (`key_provenance.jwk`,
    `embedded_key.jwk`), and key findings say where each key came from: `key` with
    its source, method and thumbprint, `embedded_key` with its location and thumbprint;
    `verify.weak_key` adds the `criterion` it fails. The embedded key, and its proof's
    result, is shown at level 1 (decided 2026-10-21, after review).
  - `--unsafe` has three levels: 0 masks claims and secrets, 1 (`--unsafe`) shows claims,
    2 also shows cryptographic secrets, such as a header `jwk`'s private members.
    Caller errors and the warning are the only stderr output; milestone 3 adds
    diagnostics. Decided 2026-10-21, after review: no output setting changes the exit
    code, so `--verbosity 0` with `--unsafe` is accepted and prints nothing, and a test
    checks every input at every format and level; the warning is repeated in the result
    (`warnings` in JSON; in `text` and `plain` after the findings, so that the status is
    always the first line); `--unsafe 2` is accepted beside `--unsafe=2`.
  - The JOSE header (`format.header`) is listed as values, as the claims are (decided
    2026-10-21, after review: the header as written, with a masked value as `null`,
    could not mark a masked value unambiguously). `credential.metadata` stays as it is.
- *Fixtures, negative first* (REQUIREMENTS §11), committed under `fixtures/` except the
  over-size input, which its test generates: happy Ed25519; tampered signature;
  expired; not yet valid; `validUntil` before `validFrom`; `alg: none`; `alg: Ed448`
  (unsupported by name; decided 2026-10-07 in place of ES256, which milestone 2
  implements); embedded `jwk` only (refused); `did:key` encoding
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
   years outside 0001–9999, hour 24) and decide; a test per difference. Decided
   2026-10-01: XML Schema is followed; the differences and their handling are tabled in
   ARCHITECTURE §4.
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
   format matched". Decided 2026-09-29: reading it, with a warning that it is not
   recommended, is ARCHITECTURE §10 [F1], in milestone 4.

### Milestone 2. Key material and the algorithm table

**Scope.** ES256, ES512, RS256, HS256 as prototyped (finding 5); a recorded decision on
ES384, ES256K and the PS and RS384/RS512 families ([C3]), implementing what is decided. A
caller-supplied JWK set (flag name is implementation-time), matched by `kid` else the sole
key. The rules of ARCHITECTURE §8's key and proof table, with RFC 7638 thumbprint
matching: a caller-supplied key must be the same key as the issuer key when both are
present, whatever the issuer key's source (decided 2026-10-27), and the embedded key
decides alone only with the caller's opt-in. A second opt-in lets a caller-supplied key
override the issuer key. The rules in one function, tested with every row of the table.
For each distinct key, the kinds of key it is and its proof's result (correct, incorrect
or not attempted), and which is the deciding proof key, in place of milestone 1's
separate reports of the issuer key and the embedded key. Open question, to decide with
the override opt-in: a caller-supplied key when vcrd cannot obtain the issuer key (a DID
method it does not resolve, or `did:web` without network access). The table counts that
issuer key as not present, so the caller-supplied key decides, but a key set matched by
`kid` binds no key to an issuer: a key of issuer B could give a correct proof for a
credential naming issuer A (RFC 8725 §3.8). A `kid` that is a `did:key` URL, in a
credential whose issuer gives no key, as a key the credential carries about itself:
refused without the opt-in and reported as an embedded `jwk` is, with location
`header.kid`, so that
such a credential is not blocked for want of key material (milestone 1's review of
slice 5, N12: nothing binds such a key to an issuer). The algorithm allowlist as a `Context` input and a CLI flag; policy
rejection (exit 5) distinct from unsupported (exit 6), both reported when both apply.
Binding of each algorithm to key type *and curve*. Weak-key criteria at resolution: RSA
modulus of at least 2048 bits (RFC 7518 §3.3 **[verified]**), HS256 key of at least 256
bits (RFC 7518 §3.2 **[verified]**), the EC identity point, Ed25519 `is_weak`. [Q4].
`did:key` decoding for `p256-pub` and `p521-pub`; `p384-pub`, `secp256k1-pub` and
`rsa-pub` named only. [C1] the audit-status table; [C2] the elliptic-curve crate
generation. [G2] the debugging guide run on Linux, at a time the maintainer chooses
within the milestone, so that it is ready before a Linux-only failure needs it. When
Rust 1.101 is stable (scheduled for 2026-12-24), the toolchain pin moved to it and the
guide run again on macOS, including a Step Out of `keys::resolve` and of
`runner::embedded_proof` with CodeLLDB's Variables view open: at 1.99.1 both made
CodeLLDB's memory grow without bound, and 1.101 brings rust-lang/rust#165113. Also a Step
Out of `keys::add_members` and of `keys::choose_caller_key`, which return into
`runner::verify_proofs` too (added 2026-11-25). Also, with 1.101's formatters (added
2026-11-26): whether a stock lldb, Ubuntu's, LLVM's or Apple's, still shows the enums of
slice 4's first session as a variant they do not hold. If one does, research the problem
upstream: whether rust-lang/rust or LLVM already has a report of it, and whether a fix is
already on its way to a release, before considering a report of vcrd's own. lldb's
support for Rust is still changing from release to release, and CodeLLDB's own build may
carry fixes that reach upstream later, so the likeliest remedy is a later release. If a
stock lldb shows them correctly, the image takes its lldb from Ubuntu's archive again:
CodeLLDB's package leaves `docker/debugging/Dockerfile`, and the guide's sentences on
which lldb matters change with it.

**Decided 2026-11-13**, before implementation:

- *Algorithms ([C3]).* Every signature algorithm of RFC 7518 §3.1 except `none`: HS256,
  HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384 and PS512, beside
  Ed25519 and EdDSA. ES256K is a named follow-on, ARCHITECTURE §10 [C4]; Ed448 is not
  planned. With ES384, a `p384-pub` `did:key` is decoded, so the exit criteria's codec
  that vcrd names but cannot use is `secp256k1-pub`.
- *Crates ([C2]).* RustCrypto's generation that shares `sha2` 0.11 with `ed25519-dalek` 3:
  `p256`, `p384` and `p521` 0.14, `rsa` 0.10 and `hmac` 0.13, checked when added with
  `cargo tree -d`; verification features only, and signing features only in
  dev-dependencies, for the fixture generator. A release candidate, or an advisory open
  against the chosen version, comes back for decision. The maintainer reviews the
  dependency changes of each commit.
- *The caller-supplied key set.* `--key-set <FILE>`, a JWK Set (RFC 7517 §5) and nothing
  else: a single JWK is a caller error that says what was found. A member RFC 7517 §5 says
  to ignore (a `kty` vcrd does not know, a required parameter missing, a value out of
  range) is ignored, with a warning. Matching: the header's `kid`, resolved against the
  issuer as inspect resolves it, compared exactly with each member's `kid`, and among
  equal `kid`s the members of the key type the algorithm takes; otherwise the sole member,
  when the set has one and either it or the credential has no `kid`. No match, or more
  than one member left, is a refused caller-supplied key, attributed to caller policy
  (exit 5), never a fall back to the issuer key alone. A member's `alg`, `use` and
  `key_ops` are the caller's
  policy: a key they exclude is refused. The matching here is superseded by the decisions
  of 2026-11-24, below.
- *The opt-ins.* `--allow-embedded-key` lets the embedded key decide alone, a `header.jwk`
  and a `did:key` `kid` alike; when a credential carries both and they differ, neither
  decides. `--allow-key-override` lets a caller-supplied key unlike the issuer key decide.
  Without it the issuer key decides, and a caller-supplied key unlike it is an error
  attributed to caller policy (exit 5); with it, a warning names the issuer key and its
  proof's result. ARCHITECTURE §8's S? column marks the rows each opt-in changes, E and C,
  and `keys::decide` states the rules as one function.
- *A caller-supplied key when vcrd cannot obtain the issuer key* (the open question
  above): the caller-supplied key decides, as the table has it. The issuer key not obtained
  is then a warning of its own, naming the issuer, the method and the reason, and saying
  that the two keys were not compared; the result records whether the key was matched by
  `kid` or as the sole member. Key sets bound to an issuer identifier are ARCHITECTURE §10
  [Q8], for milestone 3's configuration file.
- *Each key and its proof.* `key_provenance` lists each distinct key once, by thumbprint,
  with its `kinds` (the values of `source`), a detail for each kind, its thumbprint and
  JWK, its proof's result and, when it is refused, why; `deciding` names the deciding proof
  key, and `same_as_issuer_key` goes. A key vcrd names but cannot decode has no
  thumbprint. A symmetric key has none either, and its `k` is masked below `--unsafe=2`.
  The maintainer tries the first implementation's input and output, and this decision and
  the previous one may change then. Decided 2026-11-16, on reviewing slice 2's output:
  `text` and `plain` show every key's thumbprint from level 2, the deciding proof key's
  included, where milestone 1 showed the deciding proof key's at level 1. Level 1 says
  which kinds of key each is and where each came from.
- *A correct proof that does not count* is a warning of its own, naming the key and why
  its proof does not count: a key set member not matched, or one of several members left;
  an embedded key refused alone; one of two embedded keys that differ; a caller-supplied
  key unlike the issuer key. Key substitution keeps `verify.embedded_key_proof_correct`.
  No proof is made with an algorithm the allowlist excludes, nor with a key whose own
  `alg`, `use` or `key_ops` excludes the algorithm (RFC 8725 §3.1), nor with a weak key;
  the finding says that it was not attempted, and why.
- *Two different keys that both give correct proofs* prevent success, whatever the
  opt-ins: an error attributed to the input, naming both keys. ECDSA public-key recovery
  produces them; slice 6 has a fixture.
- *The allowlist.* `--algorithms`, comma-separated or repeated; without it, every
  supported algorithm. A name outside IANA's registry of JWS algorithms, and `none`, are
  caller errors (exit 1). A rejection is attributed to caller policy (exit 5); unsupported
  and rejected at once exits 6, with both findings.
- *[Q4].* A `Limits` field for the RSA modulus, 4096 bits by default; a larger modulus is
  attributed to caller policy (exit 5), with its size and the limit.
- *[G2].* In an Ubuntu container, from a committed `Dockerfile` with the image pinned by
  digest, by command line with `rust-lldb`, not in VS Code; after slice 3.
- *Rust 1.101.* If milestone 2 is otherwise done before 1.101 is stable, the task moves to
  milestone 3.
- *Slices*, one pull request each: (1) the rules in one function; (2) each key and its
  proof in the result; (3) caller-supplied keys and the two opt-ins, with Ed25519; (4)
  [G2]; (5) the allowlist; (6) ECDSA, with [C1] and [C2]; (7) RSA, with [S1] and [Q4]; (8)
  HMAC, with [S2]; (9) the milestone review; (10) Rust 1.101.

**Decided 2026-11-16**, before slice 3:

- *Slice 3 in two pull requests.* 3a: the caller's key policy in the `Context`, the flag
  `--allow-embedded-key`, a `did:key` `kid` as an embedded key, and every condition of
  `keys::decide` that is not met reported by a finding. 3b: the key set, its matching,
  `--allow-key-override`, and every row of the key and proof table through the binary.
- *An issuer key vcrd cannot obtain*, when another key decides, a caller-supplied key or
  the embedded key with the opt-in, is `verify.issuer_key_not_obtained`, a warning
  attributed to vcrd, in place of the error `verify.issuer_method_unsupported`: the table
  counts that issuer key as not present. A malformed `did:key` stays an input error.
- *A `did:key` `kid`*, when there is no issuer key, is an embedded key at `header.kid`. When
  it is the same key as the `jwk`, the two are one entry, at `header.jwk`; when the
  credential carries two embedded keys not known to be the same, neither decides, and
  where that is why no key decides, `verify.embedded_keys_differ` is an error attributed
  to the input. An issuer key present leaves `kid` to inspect, as before.
- *No key that may decide*, with no finding of key resolution's to say why, is
  `verify.no_key_material`, so that verify never passes without a deciding proof key.
- *The key set (3b).* `KeySet::parse` and `ContextBuilder::key_set`; a file that is not a
  JWK Set is a caller error (exit 1). Its size is capped by a `Limits` field the caller
  can raise, as the other limits are; the test of the cap generates the oversize file.
  A member RFC 7517 §5 says to ignore is `verify.key_set_member_ignored`, and a member
  with private parameters `verify.key_set_private_key`, warnings attributed to caller
  policy. An `oct` member is kept, refused as `type_unsupported` until slice 8.
  `--unsafe=2` may show cryptographic secrets, private parameters and an `oct` key's `k`
  among them, so that an issuer can debug with vcrd.
- *Matching (3b).* `ProofSuite` says whether a key fits a declared algorithm. A
  caller-supplied key records `kid` and `matched_by` (`kid` or `sole_member`). With no
  match, or several members left, each member the algorithm and the member's own `alg`,
  `use` and `key_ops` allow is tried, and those with correct proofs are listed, refused,
  with `verify.non_deciding_key_proof_correct`. Superseded by the decisions of 2026-11-24,
  below, except `ProofSuite::takes_key`.
- *New findings (3b):* `verify.caller_key_not_found`, `verify.caller_key_ambiguous`,
  `verify.caller_key_excluded` and `verify.caller_key_not_issuer_key`, errors attributed
  to caller policy; `verify.issuer_key_overridden`, a warning attributed to caller policy;
  and `verify.different_keys_correct`, an error attributed to the input (its fixture in
  slice 6).
- *Inputs for the table's rows.* The key and proof table's test builds its inputs at run
  time, with vcrd-cli dev-dependencies already in the workspace. Three inputs that show
  the rules at work are committed, in `fixtures/README.md` and `.vscode/launch.json`, and
  serve as a spot check of the generator: an embedded key with an `https:` issuer,
  refused without the opt-in and deciding with it (3a); a caller-supplied key unlike a
  `did:key` issuer key, failing without the override and deciding with it; and a
  caller-supplied key for an `https:` issuer, matched by `kid` among several (3b).

**Decided 2026-11-18**, slice 3b's details:

- *Rounds.* (a) the key set, its limit, `--key-set` and its caller errors; (b) matching
  and refusals; (c) `--allow-key-override` and the decision findings; (d) the table
  through the binary, the committed examples, the launch configurations and the
  documentation. `make ci-ok` after each.
- *The key set.* `KeySet::parse(bytes, &Limits)` and `ContextBuilder::key_set`;
  `KeySet`'s `Debug` shows no key material. Caller errors (exit 1): `key_set_unreadable`,
  `key_set_too_large`, `key_set_too_deep`, and `key_set_invalid`, whose message says what
  was found (not JSON, an array, a single JWK, no `keys`, `keys` not an array, `keys`
  repeated). Read for both subcommands, so that a bad file is always reported; consulted
  by verify only. *(Superseded 2026-11-24: read by verify only.)*
- *Its limit.* `Limits::max_key_set_bytes`, 64 KiB by default, provisional as the others
  are ([T6]); the CLI reads at most one byte past it. No CLI flag changes a limit: limits
  wait for milestone 3's configuration file. A core test raises it; a CLI test writes
  the oversize file at run time. Its depth is checked against `Limits::max_depth`, 32,
  the credential's (decided 2026-11-19): the registered members nest to depth 5, an
  RSA key's `oth` (RFC 7518 §6.3.2.7), but RFC 7517 §4–5 let other parameters nest at
  any depth, to be ignored rather than refused, and 32 already bounds the parser.
- *Members.* A member RFC 7517 §5 says to ignore is `verify.key_set_member_ignored {index,
  kid, reason}`: not an object; `kty` missing or unknown; a required parameter missing or
  not a string; a key that does not decode; `alg` or `use` not a string, `key_ops` not
  an array of strings; a parameter's name repeated (RFC 7517 §4). Private parameters are
  `verify.key_set_private_key {index, kid, parameters}`, names only. Both are warnings
  attributed to caller policy, once per verify, before any proof's findings. An `oct`
  member is kept, with no thumbprint; below `--unsafe=2` its `jwk` is `{"kty":"oct"}` and
  the key says `"masked": ["k"]`; at `--unsafe=2`, `k` is shown and listed in `reveals`.
  An empty set, or one whose members are all ignored, finds no key.
- *Matching.* The header's `kid`, resolved as inspect resolves it, compared exactly with
  each member's: one equal is `matched_by: kid`; several are narrowed by
  `ProofSuite::takes_key(algorithm, KeyType {kty, crv})`, which follows each algorithm's
  definition rather than vcrd's support (`EdDSA` takes OKP Ed25519 and Ed448, RFC 8037
  §3.1), and one left is a match, otherwise ambiguous. With no equal `kid`, the sole
  member, when the set has one and it or the header has no `kid`, is `matched_by:
  sole_member`; no header `kid` and several members is ambiguous; anything else is not
  found. The key type only breaks ties: whether the matched key fits the algorithm stays
  the suite's check (ARCHITECTURE §5), so that a mismatch is reported as one. Superseded
  by the decisions of 2026-11-24, below: adding a key set member could withdraw acceptance.
- *The matched member's own parameters* (RFC 8725 §3.1; RFC 7517 §4.2–4.4): an `alg`
  that is not the declared algorithm, a `use` that is not `sig`, or `key_ops` without
  `verify` refuses its key as `excluded_by_member`, with no proof, and
  `verify.caller_key_excluded {key, parameter, value, algorithm}`, an error attributed to
  caller policy. `EdDSA` and `Ed25519` are one algorithm when the member's `crv` is
  `Ed25519` (RFC 8037 §3.1; RFC 9864 §2.2), with `verify.caller_key_alg_alias {key, alg,
  declared}`, a warning attributed to caller policy, since a verifier that compares the
  names refuses the key (decided 2026-11-19; slice 5's allowlist treats the names
  alike). A matched key vcrd cannot use is refused as `type_unsupported`, with
  `verify.caller_key_type_unsupported {key, kty, crv}`, an error attributed to vcrd: a
  refused caller-supplied key decides, so something must say why. Revised 2026-11-24, below: a member's own parameters decide
  whether it is eligible.
- *No match, or several left.* A refused caller-supplied key with no thumbprint stands in
  the list, `refused` `not_found` or `ambiguous`, so that the rules see a caller key and
  never fall back to the issuer key; `verify.caller_key_not_found {kid}` and
  `verify.caller_key_ambiguous {kid, candidates}`. Each member the algorithm and its own
  parameters allow is then tried; those with correct proofs are listed, refused as
  `member_not_matched`, with `verify.non_deciding_key_proof_correct`. A member whose key
  is a listed key joins it (`kinds` gains `caller_supplied`, with its `kid` and no
  `matched_by`) and is not the caller-supplied key the rules consult. Superseded by the
  decisions of 2026-11-24, below.
- *Output.* A caller-supplied key has `kid`, the member's own, and `matched_by`; a
  finding's key reference gains `kid`. `keys` is in the order of precedence, the
  caller-supplied key first. `kid` and `matched_by` are superseded by the decisions of
  2026-11-24, below.
- *The override.* `--allow-key-override`. Without it, `verify.caller_key_not_issuer_key
  {caller_key, issuer_key}`, an error attributed to caller policy; with it,
  `verify.issuer_key_overridden {issuer_key, proof}`, a warning attributed to caller
  policy. An issuer key with no thumbprint is not known to be the same key. A finding
  that refuses a key that does not decide is a warning, so that the outcome follows
  `keys::decide`, as `verify.issuer_key_not_obtained` does; `did_key_undecodable` stays
  an error.
- *Two different keys correct.* `verify.different_keys_correct {keys}`, an error
  attributed to the input, tested with a synthetic decision until slice 6's fixture.
- *The table through the binary.* Every row with each of the four settings of the
  opt-ins, with inputs a generator in `vcrd-cli/tests/support` builds at run time: a
  `did:key` issuer when the issuer key is present and an `https:` one otherwise, a header
  `jwk` for the embedded key, a one-member key set without `kid` for the caller-supplied
  key, and the row's correct key, or a fourth key, as signer. vcrd-cli dev-dependencies:
  `ed25519-dalek`, `bs58`, `sha2` and `base64`.
- *The committed examples*, from the same generator, with an ignored `regenerate` test
  and a test that the committed bytes are what it produces:
  `fixtures/caller-key-unlike-issuer.jwt` and its `.jwks.json` (launch configuration
  "vcrd: allow-key-override"), and `fixtures/key-set-kid.jwt` and its `.jwks.json`, three
  members, one the signer's ("vcrd: key-set"). Neither is in the input picker,
  which cannot pass `--key-set`.
- *`verify.caller_key_not_issuer_key` in round (b)*, not (c) (decided 2026-11-19): once
  caller-supplied keys exist, a key unlike the issuer key leaves a condition unmet, and
  without the finding a round committed alone would let verify pass.
- *To check before slice 3b's pull request:* every `dead_code` annotation left in the
  workspace. (The strict-or-lenient setting's default and flag were decided on
  2026-11-24.)

**Decided 2026-11-24**, on reviewing round (c): the key set's matching, superseding the
matching of 2026-11-13, 2026-11-16 and 2026-11-18. Those rules counted members ("the
sole member"), so adding a member could withdraw acceptance: `{issuer key}` passed, and
`{another key, issuer key}`, neither with a `kid`, failed in either order.

- *Terms.* A *key* is the cryptographic material: a public key, or an `oct` key's secret.
  A *key set member* is one JWK in the set: one key, with parameters such as `kid`,
  `alg`, `use` and `key_ops`. "Member", not "entry", is the set's term, and "parameter",
  RFC 7517 §4's, names a JWK's own JSON members, so that the two senses of "member" never
  meet. The code says the same: `KeySetMember`, `KeySetMemberProblem` (with
  `parameter_missing`, `parameter_invalid` and `parameter_repeated`), `MemberExclusion`,
  `verify.key_set_member_ignored`, the refusals `member_not_matched` and
  `excluded_by_member`, `matched_by: sole_member`, and `parameters` in
  `verify.key_set_private_key` and `parameter` in `verify.caller_key_excluded`. A member
  with no key vcrd can read is one RFC 7517 §5 says to ignore. `key_provenance.keys` lists
  keys, each once, by thumbprint; a caller-supplied key names each member it came from,
  by its position in `keys` and its `kid`, in place of `kid` and `matched_by`.
- *The set is unordered:* any order of its members gives the same result. A property
  test runs permutations.
- *Eligible members.* A member is eligible for a proof when the declared algorithm takes
  its key type (`ProofSuite::takes_key`); its own `alg`, `use` and `key_ops` allow the
  algorithm, `EdDSA` and `Ed25519` being one algorithm for an Ed25519 key (decided
  2026-11-19); and, in strict mode, its `kid` does not contradict the header's: the
  member has none, the header has none, or the two are equal, the header's resolved as
  inspect resolves it.
- *The caller-supplied key* is the key of the eligible member whose proof is correct.
  `keys::decide` and the key and proof table apply unchanged; two different keys with
  correct proofs are `verify.different_keys_correct`. When no eligible member's key gives
  a correct proof, verify fails whatever is chosen, and the choice decides only which
  finding explains it: the member holding the issuer key, when eligible; otherwise the
  sole eligible member; otherwise a refused caller-supplied key that stands in, with
  `verify.caller_key_not_found` (its detail settled below). Proofs are made with the key of every member that vcrd can use and whose key
  type the algorithm takes, eligible or not, so that a member whose key would verify is
  named; the size limit bounds their number. `verify.caller_key_ambiguous` and the
  refusals `ambiguous` and `member_not_matched` go. `verify.caller_key_excluded` names a
  member whose key's proof would be correct and whose own parameters exclude the
  algorithm.
- *Adding a key that didn't sign never turns a pass into a failure*, in lenient mode. A
  property test adds members whose keys' proofs are incorrect. Its name, if one is
  needed, is monotonicity.
- *Strict and lenient,* one setting: `--key-set-checks <strict|lenient>`, strict by
  default. `strict` is accepted too, so that a command line can override milestone 3's
  configuration file when that sets `lenient`. Problems found when the file is read: a
  member RFC 7517 §5 says to ignore, private parameters, and one `kid` on two different
  keys of one key type. Lenient: warnings, and the rest of the set is used. Strict: the
  set is rejected, a caller error (exit 1), `key_set_rejected`, whose message lists each
  problem. Members that share a `kid` and differ in key type are RFC 7517 §4.5's
  equivalent alternatives, allowed in both modes. One key in two members is
  `verify.key_set_key_repeated`, a warning in both modes. Problems found against a
  credential: a member whose key's proof is correct and whose `kid` differs from the
  header's, `verify.key_set_kid_not_header_kid`, and the `alg` alias. Lenient: a warning, and
  the member is eligible. Strict: the member is ineligible, and the finding is an error
  when that is why no key decides, a warning otherwise. Neither mode treats a member the
  algorithm cannot use, or one whose own parameters exclude it, as a problem: it is not
  eligible, as an encryption key in a published set is not.
- *Making a key set from a credential* stays supported: the recipe, the issuer key's
  `jwk` from `--format json`, with the header's `kid`, is documented, and a test runs it
  and verifies with the set it makes (exit 0). A command that writes a key set from a
  credential, and one that merges key sets, useful for building test inputs, are named
  follow-ons for milestone 3's CLI or later.
- *A committed example of the setting*, in round (d), beside the two decided on
  2026-11-18: a credential and a key set whose member holding the signer's key carries a
  `kid` other than the header's, failing with `--key-set-checks strict` and passing with
  `lenient`, both
  with `verify.key_set_kid_not_header_kid`. Its launch configuration picks the value, which is
  always passed, so a picker suits it.
- *Weak keys in a `jwk` or a key set member,* to slice 6: an Ed25519 key of small order
  there is not refused when it is read, as a `did:key` one is; `verify_strict` rejects
  its signature, so only the finding is less precise. Slice 6 brings the EC identity
  point, and with it one weak-key check over every key source and type (milestone 2's
  scope), whose first test is this case.
- *Settled before the round,* the same day:
  - Findings checked against a credential (a `kid` not the header's, the `alg` alias)
    name only a member whose key's proof is correct; the others' keys did not sign.
  - A finding that names a member that is not eligible and whose key's proof is
    correct (`verify.caller_key_excluded`; in strict mode, the `kid` and alias
    findings) is an error when no eligible member's key gives a correct proof, and a
    warning otherwise. Its key has no `verify.non_deciding_key_proof_correct`: the
    finding already says the proof is correct. `verify.caller_key_not_found` stays an
    error beside it, its detail the header's `kid` alone: a key set usually holds every
    key the caller trusts, so a reason for each member would be mostly irrelevant, and
    the members that matter are named by their own findings.
  - "The sole eligible member" counts distinct keys: two members holding one key are
    one, so repeating a member changes nothing but the repeated-key warning.
  - Two different eligible keys with correct proofs, which only a crafted key gives:
    `verify.different_keys_correct`, with the issuer key consulted when it is one of
    them, and otherwise the one with the least thumbprint, so that member order does
    not show.
  - The key type for one `kid` on two different keys is `kty` and `crv`: Ed25519 and
    Ed448, or P-256 and P-384, under one `kid` are alternatives.
  - A member's `kid` is compared as written; the header's is resolved. A temporary
    example with a relative member `kid` is to be tried before deciding otherwise.
  - The order property compares the verdict, the deciding key, each key's kinds, proof
    result, refusal and members' `kid`s, and the findings by code, attribution and
    severity; not member indexes, nor the order non-deciding keys are listed in, which
    follow the file.
  - `vcrd inspect` does not read the key set, as it ignores the other key options;
    superseding 2026-11-18's "read for both subcommands".
  - The `kid` finding is `verify.key_set_kid_not_header_kid`, and its refusal
    `kid_not_header_kid`, as `verify.caller_key_not_issuer_key` is named; the alias's
    refusal, in strict mode, is `alg_alias`. One `kid` on two different keys of one key
    type is `verify.key_set_kid_repeated`.
  - In `text`, every key from a member reads "caller-supplied key, from key set member
    N (kid …)", chosen or not; when none is chosen, the refused key that stands in is
    the one the rules consult. Saying "key set member N" alone was considered, and kept
    out: the chosen key would no longer read as caller-supplied.
- *Order of work.* A round before (d): matching changed red then green, the setting and
  its flag, the two property tests, the members each key in the output came from, and
  the documentation. Round
  (c), not yet committed, is committed first or with it, as the maintainer chooses.

**Decided 2026-11-25**, before round (d):

- *The table's inputs.* All 37 rows alike, from the generator in `vcrd-cli/tests/support`;
  the ten committed fixtures that served milestone 1's rows keep their own tests. A row
  with an issuer key names its `did:key`, with the DID URL as `kid`; any other names
  `https://issuer.example`, with `iss` equal to it and no `kid`, so that the header names
  no key (VC-JOSE-COSE §4.2 asks for an absolute `kid` only when `iss` is absent). The
  generator stays in vcrd-cli with its four dev-dependencies, as decided on 2026-11-18;
  whether to merge it with vcrd-core's is milestone 6's.
- *What the table test checks,* for each row with each of the four settings of the
  opt-ins. From the table's cells: the keys' kinds, which kinds are one key, each proof's
  result, and exit 0 exactly when S? permits success. From the rules, each written once
  in the test and citing its source: the deciding proof key (rule 2); each finding
  docs/findings.md conditions on the keys; and the error findings exactly, whose
  attributions give the exit code by ARCHITECTURE §6's precedence. Without an expected
  value: an opt-in the rules make irrelevant to a row leaves the output as it is without
  it, byte for byte, in 96 of the 148 runs (the embedded key's opt-in matters only when
  that key is the only one, the override only when the caller-supplied and issuer keys
  differ). Nobody reviews the cases one by one; a disagreement is examined by itself.
- *The third example:* `fixtures/key-set-kid-not-header-kid.jwt` and its `.jwks.json`, an
  `https:` issuer whose header `kid` is the signer's JWK Thumbprint URI (RFC 9278), and
  one member, holding the signer's key, whose `kid` is the bare thumbprint. Its launch
  configuration, "vcrd: key-set-checks", picks the value.
- *The input picker* offers every example and fixture except the key sets and the
  credentials beside them, each of which a configuration of its own names.
- *The debugging guide's rows for `keys::add_members` and `keys::choose_caller_key`* stay
  inside the function, as those for `resolve` and `embedded_proof` do (the Rust 1.101
  task, above).
- *The guide's tables of where to break* each name, in the line before them, the launch
  configuration that runs their rows, which must offer each row's input; every
  configuration that runs a committed input has a table, the two opt-ins' included.

**Decided 2026-11-25**, before slice 4 ([G2]):

- *The environment.* Docker Desktop on the maintainer's Mac, so the run is on arm64; CI's
  runners are x86_64. `ubuntu:26.04`, the release CI's `ubuntu-latest` runs, named in full
  and pinned by the digest of its multi-arch index, with apt read from Ubuntu's snapshot
  archive at a fixed time, so that the image is the same whenever it is built. Only
  `ca-certificates`, which apt needs to reach the snapshot over HTTPS, and `openssl`, which
  it depends on, come from the archive as it is at the build. The digest and the
  snapshot's time move together when the guide is run again, not by dependabot. The
  image holds Ubuntu's `rustup`, the toolchain
  `rust-toolchain.toml` names (installed by reading that file, the only one the build
  sees), an lldb (next item), a linker, and the tools the helper scripts need. It holds no
  source. It is built from `docker/debugging/Dockerfile`, apart from the helper scripts.
- *The lldb (changed 2026-11-26, after the first session on Linux).* With Rust 1.99.1's
  formatters, Ubuntu's lldb 22.1.2, LLVM's own 22.1.8 and Apple's `lldb-2103.0.34.407`
  showed some enums that carry data as a variant they do not hold. At
  `vcrd::exit::exit_code`, for `examples/ed25519.jwt`, the finding's `detail` showed as
  `KeySetKidRepeated` rather than `AlgorithmDeprecated`, and the header's `jwk` as
  `Some(Ok(…))` rather than `None`. CodeLLDB 1.12.3's lldb, `22.1.8-codelldb`, built from
  a fork of LLVM, showed them correctly, on macOS and in the container alike, through the
  same `rust-lldb`; CodeLLDB loads the formatters as `rust-lldb` does. The image takes
  CodeLLDB's lldb from its Linux package for the platform being built, arm64 or x86_64,
  each pinned by URL and by the SHA-256 its release page gives, in place of Ubuntu's
  `lldb-22`. The guide says, for both platforms, that this lldb matters. The Rust 1.101
  task, above, looks again.
- *What the container reaches.* The repository, mounted read-only; the target directory
  and cargo's directory, in named volumes; an unprivileged user, with no capabilities and
  no new privileges; 4 GiB of memory, so that a debugger whose memory grows without bound
  is stopped inside the container; the network, only for `cargo fetch --locked`. lldb
  leaves address-space randomization on (`target.disable-aslr false`) rather than have
  seccomp relaxed. If the container still cannot trace, that comes back for decision: no
  capability is added without one.
- *The run.* All of the guide, by command line with `rust-lldb`: setup, the first session,
  every row of where to break with the same inputs, breakpoints by name, a test binary,
  and the helper scripts. To begin with, the maintainer runs every container and debugger
  command, and then decides what to hand over. No row is added for a Step Out into
  `runner::verify_proofs`; the maintainer may try one.
- *The guide.* A Known-to-work table for Linux beside macOS's, each with its date, and a
  section "Linux, from the command line": the image, a first session, each launch
  configuration as a command line, VS Code's actions as lldb commands, and debugging a
  test. The tables of where to break stay shared. Checks of the Linux text in
  `vcrd-cli/tests/debugging.rs` wait until the differences between the platforms are
  understood. Until then the guide names the Dockerfile rather than quoting it, so that
  no unchecked copy can differ from it.
- *No CI job* builds the image; the milestone review (slice 9) reconsiders it.
- *Records.* ARCHITECTURE §10 [G2] closes once the maintainer has run the guide. What the
  run found and changed goes in the pull request, and into the milestone's review record
  in slice 9.
- *Added 2026-11-26, for this slice.* Each is designed, and the design approved, before
  it is built:
  - *The command line on both platforms.* The guide documents running `rust-lldb` with
    CodeLLDB's lldb first on `PATH` on macOS too, from the CodeLLDB extension's
    `lldb/bin`, beside the container's on Linux. The first session and the tables of
    where to break serve both.
  - *A check of lldb's output on both platforms.* A command-line session run in batch
    mode, whose output is checked on macOS and on Linux. Comparing the two platforms'
    output is not enough: at first both showed the same wrong variants. The expectations
    come from outside the debugger: vcrd's own `--format json` for the same input, and
    rules taken from vcrd's source, such as that a finding's `detail` is the variant its
    `code` names. Where and when it runs (by hand, in the container, in CI) is part of
    its design. On macOS it is a debugger run outside a container, which the maintainer
    starts.
- *The command line is for experts (decided 2026-11-26).* No way of running a debugger
  gets a complete guide of its own. VS Code with CodeLLDB has the whole guide. The command
  line, whose users, people or agents, are taken to be experts, gets what it takes to
  start an lldb that works and run one session with it, the first session, on macOS and on
  Linux. This narrows *The run* and *The guide*, above: no row of where to break is run
  again on Linux, and the guide gives no launch configuration as a command line, no table
  of VS Code's actions as lldb commands, and no test binary from the command line. The
  helper scripts are run once on Linux, and whether the `.lldbinit` setting is needed is
  checked. The command line on both platforms moves into round (b).
- *Rounds:* (a) the Dockerfile, the setup and the first session; (b) the command line on
  both platforms, Known to work, the helper scripts and the `.lldbinit` check on Linux,
  and the records; (c) the check of lldb's output.

**Delivers.** `vcrd verify` for RFC 7518's signature algorithms, with caller keys, the
embedded-key opt-in, the override opt-in and the allowlist; the keys and their proofs'
results for every row of ARCHITECTURE §8's key and proof table.

**Exit criteria.** Fixtures: algorithm confusion (HS256 with the issuer's public-key bytes
as secret, reported as key-type mismatch, not as unsupported); `none`; unsupported
(ES256K); policy-rejected; unsupported and policy-rejected at once (exit 6, two findings);
key substitution (embedded proof key correct, issuer proof key incorrect, exit 4); a
caller-supplied key unlike a `did:key` issuer key, with its proof correct, not successful
without the override opt-in and successful with it; embedded-only
refused, and accepted with the opt-in (exit 0, the deciding key's `kinds`
`credential_embedded`); RSA 1024 and HS256 128-bit keys (weak-key findings); a
`secp256k1-pub` `did:key` (named, exit 6); ES512 happy path, the EUDI evidence point of
REQUIREMENTS §10.

**Closes.** [S1], [S2], [C1], [C2], [C3] (decision recorded; anything left out is a named
follow-on), [Q4], [G2].

**Milestone review.** Texts: RFC 7518 §3.1–3.6, including §3.4's `R || S` encoding at 64,
96 and 132 octets **[verified]** and §3.6's "MUST NOT accept Unsecured JWSs by default"
**[verified]**; RFC 7517; RFC 7638; RFC 8037; did:key v0.9 create and read algorithms;
VC-JOSE-COSE §4.1–4.2 and §5's "verifiers SHOULD strive to minimize the processing of
untrusted data" during key discovery **[verified]**. Known inputs: the did:key v0.9 table,
as extracted by the fetch tool, lists codecs `0xe7`, `0xec`, `0xed`, `0x1200` and `0x1201`
only; `p521-pub` (`0x1202`) and `rsa-pub` (`0x1205`) come from the multicodec registry,
which that review did not read. Record the source for each codec when it is implemented,
and treat P-521 `did:key` as an extension beyond the method spec's table.

Also read (decided 2026-11-13): RFC 7518 §2's Base64urlUInt and §6.1–6.4's key
parameters, on which the thumbprints that compare keys depend, and §3.5's PSS salt
length; RFC 8725 §3.1–3.5, and §3.8 again for key sets; RFC 8017 §8.1.2, §8.2.2 and
§9.1.2, with the `rsa` crate's verification code; FIPS 186-5 §6.4.2 and SEC 1 v2.0
§2.3.3–2.3.4, with the ECDSA crates' code; RFC 9864 §2.1, for fully specified ECDSA names
in JOSE; IANA's JOSE registries, for the allowlist's names; RFC 7515 Appendix A.1–A.4 and
RFC 7520 §4.1–4.4, as known-answer tests; the terminology check (REQUIREMENTS §15) for
the milestone's new terms; and ARCHITECTURE §9's rows. Known input: RFC 8725 §3.1 has each
key used with exactly one algorithm, checked at the time of the operation, while an RSA
key serves RS256 and PS256 alike and only a caller-supplied JWK's `alg` can bind it to
one.

### Milestone 3. The CLI contract, configuration and hardening

**Scope.** The configuration file (TOML in the per-OS directory) and environment variables,
with the precedence flag > env > config > default resolved per path for designations
(REQUIREMENTS §8). Per-path show/hash/mask designations with the `reveals` list; an initial
hash construction chosen and labeled provisional (REQUIREMENTS §16 item 18 stays open).
`vcrd formats` and `vcrd suites`. Man pages and completions from `clap`. [Q2] decided.
The input's source in the result (decided 2026-10-22): `input.source`, `file` or `stdin`,
and `input.path` as given on the command line, never made absolute; in JSON always, and in
`text` and `plain` at levels 1–3 just after the status. With it, the key set's (decided
2026-11-25): a top-level `key_set` beside `input` when verify reads one, with `path` as
given on the command line, never made absolute, `bytes`, `members` and `checks`, shown
where `input`'s source is. vcrd-core's `Report` carries both, each with a label the access
mode supplies, so that every access mode reports them alike.
[Q7] decided and built for credentials (decided 2026-10-24, in milestone 1's review): a
result that conforms exactly to VCDM 2.0 §7.1's, with VCDM 2.0 §7.2's problem types,
through `--format json`, a format of its own, or a conforming part of the envelope;
milestone 4 extends it to presentations.
Stderr diagnostics per verbosity level. [T2] `cargo-fuzz` targets for the JWS parser and
the depth prescan, seeded from fixtures, in a workspace-excluded `fuzz/` on a nightly job.
[T5] coverage with the ratchet policy text ready for `CONTRIBUTING.md`. [T6] structural
limits derived from a corpus nobody on the project wrote: the W3C VC test-suite fixtures,
VC-JOSE-COSE §8's examples, and outputs of the oracles REQUIREMENTS §11 names, each with
source and license tracked. Property tests: base64url and JWS split/join round trips, and
the depth prescan agreeing with `serde_json`'s rejection at 128. The performance tripwire
and a `criterion` baseline (REQUIREMENTS §11).
*Quadratic loops over a key set's members* (noted 2026-11-24): `KeySet::kids_repeated`
and `KeySet::keys_repeated`, and `keys::add_members` and `keys::choose_caller_key`, each
marked "Quadratic in the members" in its comment. `Limits::max_key_set_bytes` bounds them:
measured on 2026-11-24 with a debug build, `vcrd verify` of the curated example with sets
of `oct` members, each with its own `k` and `kid`, took 0.01 s for 400, 0.02 s for 800 and
0.09 s for 1,600 (61,791 bytes, near the 64 KiB default); the sets were made with
`jq -cn --argjson n 1600 '{keys: [range(0; $n) | {kty: "oct", k: "k\(.)", kid: "i\(.)"}]}'`.
Left quadratic at least until this milestone (decided 2026-11-25), and perhaps past the
first release: when the configuration file lets the limit be raised, decide whether to
make them linear, with maps keyed by `kid` and key type, by key, and by member, or to cap
the number of members; either way, give the performance tripwire a key set at the limit.

**Delivers.** `vcrd` usable unattended by a CI job or agent with a config file and no
flags; the same result whether a setting came from a flag, the environment or the file.

**Exit criteria.** Black-box tests for every precedence combination; the canary test
extended to designations and hashing; fuzz targets run for a fixed budget in CI without a
panic; limit defaults documented with the measuring command and the corpus.

**Closes.** [Q2], [Q7], [T2], [T5], [T6].

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
[F1]: JWS JSON serialization read for credentials and presentations, with its warning and
per-signature results.

**Delivers.** `vcrd verify presentation.jwt` with expected-nonce and expected-audience
flags (names implementation-time), reporting the holder proof and each contained
credential separately.

**Exit criteria.** Fixtures: a presentation with two enveloped credentials, one expired
(exit 3; presentation verify passed; credential 1 passed; credential 2 inspect failed); a
presentation enveloping an `application/vc+sd-jwt` credential (contained parse fails,
named by media type, attributed to vcrd); wrong nonce (holder proof fails replay binding);
no parameters (`not_evaluated`); nesting over the cap; a self-asserted credential without
`holder`.

**Closes.** [F1]; and implements the containment design (ARCHITECTURE §3, §4, §6).

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
`proof` map, or a proof without `type`, `verificationMethod` or `proofPurpose`, is an
"impossible" case of REQUIREMENTS §4's blocking rule, reported in the structure milestone 1
settled (REQUIREMENTS §16 item 20); `expectedProofPurpose` joins `Context`
(`assertionMethod` for credentials, `authentication` for presentations). Proof sets
(§2.1.1); proof chains as a follow-on. The canonicalization budget as a verify-phase
bounded-out finding attributed to vcrd; note that REQUIREMENTS §4's "dangerous, internal"
block requires *inspect* to predict the cost, so either a cheap predictor (blank-node
count over a threshold) is added at inspect or the budget itself is the control, and the
choice is written down. Vendored vectors with source and license: the RDFC-1.0 test suite,
EdDSA cryptosuites Appendix B, VC test-suite fixtures. [T1] the two-branch VC-API spike.
Data Integrity presentations as the per-format follow-on PR: §4.4 steps 6 and 7 map
directly onto REQUIREMENTS §10's expected domain and challenge **[verified]**. [F2]
VCDM 1.1's JWT encoding, beside the JSON-LD format, since both bring a second set of
data-model checks: when they arrive, decide whether the VCDM checks become a registry
extension point of their own (ARCHITECTURE §5).

**Delivers.** `vcrd verify credential.jsonld` for both cryptosuites, offline, against
`did:key` and caller-supplied keys; an unpinned or inline `@context` reported at error
severity with the prominence REQUIREMENTS §12 demands.

**Exit criteria.** RDFC-1.0 vectors pass; Appendix B vectors verify; a poison-graph fixture
trips the budget and fails closed; `jsonld` builds alone and within
the full set, under ARCHITECTURE §2's rules; the review is complete.

**Closes.** [Q1], [T1], [F2].

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
services of REQUIREMENTS §11 later. A decision on whether to merge the two test-input
generators, in `vcrd-core/tests/fixtures.rs` and `vcrd-cli/tests/support`, into one that
other access modes can use too, such as a test-only workspace crate (noted 2026-11-25;
milestone 2 keeps them apart, as decided on 2026-11-18). [D1], [D2]. The threat model promoted to
`docs/threat-model.md` (REQUIREMENTS §12). README quickstart pointing at `examples/`.
`cargo-dist` binaries, crates.io through Trusted Publishing, `Cargo.lock` tagged.
`schema_version` stays 0 at 0.1.0 and is declared 1 in a later 0.x once external
consumers have used it (REQUIREMENTS §9). [D3] documentation clean-up. The maintenance
document, below.

**The maintenance document** (booked 2026-11-27, to be written in this milestone): the
tasks done on a regular basis, each with what makes it fall due, how it is done, and what
it records. Two questions shape it. First, which parts can be automated: as many as
possible, whether by a reminder, a check that fails, or a script that looks values up.
Second, how far apart each task falls, which varies widely: Rust ships a release every six
weeks, Ubuntu an LTS every two years, and `test-powerset`'s running time changes much only
while features are being added. The tasks known so far:

- *Dependabot's pull requests*, for cargo and GitHub Actions (`.github/dependabot.yml`),
  reviewed and merged. Dependabot covers none of the tasks below.
- *The toolchain pin*, moved to each new stable Rust (REQUIREMENTS §13):
  `rust-toolchain.toml` and `rust-version` together, about every six weeks while
  development is active, with the non-blocking latest-stable CI job as early warning. Each
  move runs the debugging guide again, since the lldb formatters come with the toolchain,
  and checks whether a stock lldb now shows the enums slice 4 found wrong. If one does,
  CodeLLDB's package leaves the image (milestone 2, the Rust 1.101 task).
- *The debugging image*: its apt snapshot time, its base image's digest and its CodeLLDB
  version moved together, and the debugging guide run again (milestone 2, slice 4).
  CodeLLDB on the maintainer's Mac updates itself in VS Code, so the image's version falls
  behind unless it is moved with it.
- *The image's Ubuntu release*, following CI's `ubuntu-latest` to the next LTS, every two
  years or so.
- *The weekly CI run's failures*: a new RustSec advisory against an unchanged `Cargo.lock`.
  The failure is emailed to whoever last changed the schedule line in `ci.yml`.
- *The tools the Makefile pins*: cargo-hack, cargo-deny and cargo-audit.
- *The cryptographic crates' audit status* ([C1], recorded in slice 6 of milestone 2). A
  release candidate, or an advisory against a chosen version, comes back for decision
  (milestone 2, decided 2026-11-13).
- *The standards vcrd implements*, checked for updates, especially the cryptographic
  suites; and the registries and data it depends on: IANA's JOSE algorithm registry (the
  allowlist), the multicodec table (`did:key` codecs) and, from milestone 5, the pinned
  JSON-LD contexts.
- *`test-powerset`'s running time*, which doubles with each feature of vcrd-core: moved back
  to the weekly schedule if it grows slow (`ci.yml`). It changes much only during active
  development.
- *The examples' validity*: `examples/ed25519.jwt` is valid until 2031-01-01. The tests use
  a fixed clock, but a run against the system clock sees it expired after that date. This
  one falls due once.

**Delivers.** Installable `vcrd-cli` and prebuilt binaries; `vcrd-core` on docs.rs.

**Exit criteria.** The release pipeline runs from a tag; a semver-checks baseline exists;
the changelog is generated; every §10 item is closed or carried with its tag.

**Closes.** [P1], [P2], [P5], [P6], [T4], [T7], [D1], [D2], [D3].

**Milestone review.** Re-run every prior milestone's review list against the release
candidate, since REQUIREMENTS §11's practice is cumulative, and run the terminology check
of REQUIREMENTS §15 over every standard now in scope.

## Deferred past the first release

- **SD-JWT VC** (REQUIREMENTS §10's near-term roadmap): [Q3] first, since a withheld claim
  is neither present nor absent in `Document`; `cnf` holder binding.
- **Open Badges inspection and verification.** Consider supporting Open Badges 2.0 and
  Open Badges 3.0 with appropriate warnings findings for credentials that are not
  cryptographically signed.
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

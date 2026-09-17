# Prototype findings

Answers to the seven questions in [prototype-goals.md](prototype-goals.md), from a
throwaway VC-JWT spike on branch `spike/vc-jwt`, whose code sits beside this document.

The code is disposable; this document is not. Where a finding should change
[REQUIREMENTS.md](REQUIREMENTS.md) — the copy kept in this directory, as it stood when
the spike ended — the proposed edit is stated inline and collected in
[the disposition](#16-disposition) at the end.

File references and shell commands in this document are relative to this directory.

## What was built

Bytes → parse → validate → verify → rendered `text`/`json`/`plain` with real exit codes,
as the goals document asked. Scope: VC-JOSE-COSE (VCDM 2.0) over compact JWS; five
algorithms (EdDSA, ES256, ES512, RS256, HS256); `did:key` and caller-supplied JWK sets;
no network, no JSON-LD.

| | |
|---|---|
| Code | 4,550 lines across `vcrd-core`, `vcrd-cli`, `fixtures-gen` |
| Tests | 41 (27 black-box CLI, 14 core unit), all green |
| Fixtures | 14, negative-first |
| Algorithms verified end to end | EdDSA, ES256, **ES512/P-521**, RS256, HS256 |

Reproduce:

```bash
cargo test --workspace && ./target/debug/vcrd verify fixtures/expired.jwt --now 2026-08-22T12:00:00Z
```

Building the negative cases first was the right call and is worth repeating on the next
format. Every finding below came out of a failure fixture; the four happy-path controls
found exactly one thing between them (that ES512 works).

---

## 1. The shape of the graduated result

**Decision.** `Report` is returned **by value**. `Result` is reserved for caller faults
and never used for credential-level problems. The phases are `parse`, `inspect`, and
`verify` (finding 7). Each tier's outcome is a `Stage<T>` with
four variants, findings accumulate as a `Vec` per tier, and **a failed tier carries the
output it produced**, not only its findings.

```rust
pub fn verify(bytes: &[u8], ctx: &Context, registry: &Registry) -> Report;

pub struct Report {
    pub input: InputSummary,
    pub parse: Stage<ParseOutput>,
    pub validate: Stage<ValidateOutput>,
    pub verify: Stage<VerifyOutput>,
    pub not_evaluated: Vec<NotEvaluated>,
}

// Decided structure. The prototype has no `NotRequested`, and its `Failed` carries
// only findings (vcrd-core/src/model.rs:132).
pub enum Stage<T> {
    NotRequested,
    NotReached { blocked_by: Tier },
    Failed { output: T, findings: Vec<Finding> },
    Passed { output: T, findings: Vec<Finding> },
}

pub struct Finding {
    pub code: &'static str,   // stable machine identifier
    pub tier: Tier,
    pub blame: Blame,         // Input | Policy | Vcrd | Environment
    pub severity: Severity,
    pub detail: FindingDetail,   // 26 typed variants, no English
}
```

**Each variant is semantically significant.** "Never got here" is a materially different
answer from "got here and failed", and a type with fewer variants forces one of them to
misreport. Likewise, a tier that an earlier failure prevented is a different answer from
a tier the operation never requested. Each variant gives the CLI an accurate result to
render for a tier that did not run.

**`blame` is the field that makes §6's diagnosability real**, and it turned out to
carry more weight than expected — it drives the exit code (below), and the feature-gate
matrix found a bug purely because a blame value was wrong.

**Findings accumulate; they do not collapse.** A credential can be simultaneously
signed with an algorithm vcrd does not support *and* one the caller forbade, and the
report says both. `Result<_, E>` cannot; `Vec<Finding>` costs nothing.

**Evidence that this works.** `expired.jwt` produces `validate = Failed` and
`verify = Passed` in the same `Report` — a correctly-signed, expired credential
reporting both facts. `vcdm11-mapping.jwt` produces three at once: unimplemented
profile, a concrete `exp`-vs-`expirationDate` disagreement, and a valid signature.

### A failed tier carries the output it produced

**Decision.** `Failed` carries the tier's output alongside its findings. vcrd's aim is
to give a developer as much information about a credential as possible, and a tier that
fails has usually established facts on the way to failing.

The prototype discards that output in two places, both verified:

```bash
./target/debug/vcrd verify fixtures/expired.jwt --now 2026-08-22T12:00:00Z --format json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('stages:', {k:v['status'] for k,v in d['stages'].items()})
print('credential.temporal_status:', d['credential'].get('temporal_status'))
print('findings:', [f['code'] for f in d['findings']])
"
```

```
stages: {'parse': 'passed', 'validate': 'failed', 'verify': 'passed'}
credential.temporal_status: None
findings: ['validate.expired']
```

- **Inspect** (the prototype's `validate` phase). vcrd computed that the credential is expired, but the structured
  temporal status is `None`: `validate_jwt_vc` builds the output
  (`vcrd-core/src/validate.rs:108`) and returns `Stage::Failed { findings }` when any
  finding is an error (`:110`), and the CLI reads temporal status only from a passed
  tier (`vcrd-cli/src/view.rs:254`). The fact survives only inside the finding's detail.
- **Verify.** Failed verification discards every proof result, including key provenance
  (`vcrd-core/src/pipeline.rs:98`); see finding 6.

With the same output type in `Passed` and `Failed`, a consumer reads a tier's output the
same way whatever its status. The cost falls on the output types: anything a tier may
not reach before failing has to be represented explicitly — for example, temporal
status when inspection stops at an unimplemented profile, or the document fields of a
token whose header decoded but whose payload did not — rather than by dropping the whole
output.

### `NotRequested`: a tier the operation did not include

**Decision.** `Stage<T>` has a fourth variant, `NotRequested`, for a tier the operation
does not include. `NotReached { blocked_by }` is reserved for a tier an earlier failure
prevented: a `parse` failure prevents both later phases, and an `inspect` failure
prevents `verify` only when verification would be impossible or dangerous (finding 7).
When `inspect` blocks `verify`, the result must identify the findings responsible and
which of the two reasons applied.

The prototype has only `NotReached`, which can say that an earlier tier prevented this
one but not that the operation never included it, so `inspect` reports that verification
was blocked by the middle phase:

```bash
./target/debug/vcrd inspect fixtures/happy-ed25519.jwt --now 2026-08-22T12:00:00Z --format json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['stages']['verify'])"
```

```
{'status': 'not_reached', 'blocked_by': 'validate', 'finding_codes': []}
```

That is false twice over: the `inspect` operation never verifies, whatever the middle
phase concludes, and nothing in this credential would block verification
(`vcrd-core/src/pipeline.rs:158` sets the value unconditionally). With `NotRequested`,
`inspect` reports verification as not requested.

### Is adding SD-JWT additive? Measured, not guessed.

Adding one variant to `FormatDetail` broke **exactly two** irrefutable `let` bindings —
one in core, one in `vcrd-cli`. Then, marking the enum `#[non_exhaustive]` and going
back to a *single* variant broke the CLI immediately (`pattern &_ not covered`).

So: `#[non_exhaustive]` converts the downstream break into a no-op, at the price of
every external consumer writing a `_ =>` arm today and deciding what it renders. It
does nothing for core's own matches — those break either way, which is fine, because
core is where a new format is being added.

**Take `#[non_exhaustive]`.** The cost is one wildcard arm per frontend, paid once. The
alternative is a breaking change for every consumer the first time a format lands.

### One thing to know

**A single top-level `status` word is lossy and should be documented as such.** It
cannot express "expired but correctly signed"; only `stages` can. Keep it as a
convenience, but the schema documentation must point consumers at `stages`.

> **Proposed REQUIREMENTS change** — §6's "graduated success" bullet should name the
> per-tier outcomes (not requested, not reached, failed with its output, passed) and
> the accumulate-don't-collapse rule explicitly, and §6's
> diagnosability bullet should name a blame/attribution field as the mechanism for
> "whose side it's on" rather than leaving it as a property to be achieved somehow.

---

## 2. Is `vcrd-core`'s struct layout the public JSON schema?

**Decision. No.** `vcrd-core` derives `Serialize` on nothing. `vcrd-cli` owns an
explicit view model with a `schema_version`. During initial development the schema
version stays at `0`, meaning no compatibility promise — the same convention §13 applies
to pre-1.0 crate versions — and increments only once the schema is declared stable.

**Measured cost:** 390 lines in one file — 144 lines of schema structs, 246 lines of
mapping. Within that, the `FindingDetail` → JSON match is 43 lines for 26 variants.
That is the whole price, it is confined to one file, and it is mechanical.

**The concern that prompted question 2 in `prototype-goals.md` is confirmed.** If core
types derived `Serialize`, core's field names would *be* the wire format, and every
internal rename would silently change what consumers parse. The renames decided during
review — `Tier` to `Phase`, `blame` to `attribution` — are that case: with a view model,
core and the JSON schema each change only by deliberate edit.

**Writing both ends showed a further reason: the document carries facts `Report`
deliberately does not hold.**

- **Caller faults.** A missing file is a caller fault, and `Report` has no place for one
  by design (finding 1). The envelope carries an `error` object and a `caller_error`
  status (`vcrd-cli/src/view.rs:39`).
- **The process exit code.** Exit status is a CLI concept, computed from the report by
  `vcrd-cli/src/exit_code.rs:21`, yet the envelope carries it (`view.rs:20`) so an agent
  reading only stdout has it.

Deriving `Serialize` on core would have forced both concepts into core, across the
boundary §6 draws.

**`--format json` on failure.** Every outcome emits exactly one JSON document on stdout.
Nine top-level keys are always present, including `stages` with all three tiers; three
more — `error`, `format`, and `credential` — appear only when they apply, via
`skip_serializing_if` (open question: emit them as `null` instead, so the key set is
closed). A caller fault looks like:

```json
{ "schema_version": 1, "status": "caller_error", "exit_code": 1,
  "error": { "code": "cli.input_unreadable", "message": "…" },
  "stages": { "parse": { "status": "not_reached", "finding_codes": [] }, … } }
```

An agent never has to parse a bare stderr string. This should be a stated contract, not
an accident.

> **Proposed REQUIREMENTS change** — §9's output section should state that the JSON
> output is a versioned schema owned by the frontend, that core types are not
> serializable, and that the envelope is emitted for every outcome including tool-level
> failure.

---

## 3. Where redaction lives

**Decision.** Redaction is enforced by `vcrd-core`. Every claim value is masked by
default, and vcrd does not try to decide which claims are sensitive. A caller designates
individual claim paths to show in cleartext, to hash, or to mask, through a flag, an
environment variable, or the configuration file, under the same precedence as every
other setting. `--unsafe` reveals everything. Every reveal is reported in the result.

### The enforcement mechanism

```rust
// vcrd-core/src/redact.rs:14
pub struct CleartextGrant(());
// vcrd-core/src/redact.rs:26
pub struct ClaimValue(Value);
// vcrd-core/src/redact.rs:34
pub fn reveal(&self, _grant: &CleartextGrant) -> &Value {
```

`ClaimValue` implements no `Serialize`, and its `Debug` is hand-written
(`redact.rs:56`) — a derived `Debug` would print the value, and so would a derived
`Debug` on any struct that contains one. Plaintext is reachable only by presenting a
`CleartextGrant`, whose single constructor is called in exactly one place in
`vcrd-cli` (`view.rs:242`).

Three properties of this mechanism, each established by the spike:

- **It protects only what is routed through it.** `Document.subject` was first a plain
  `String` holding `credentialSubject.id`, and the CLI printed it in cleartext while
  masking the identical value in the claims table. The rule that follows: anything
  derived from credential content is a `ClaimValue`. Regression test:
  `subject_is_redacted_the_same_way_as_the_claim_it_duplicates`
  (`vcrd-cli/tests/fixtures.rs:278`).
- **The reveal marker must be produced by core.** In the spike, `vcrd-cli` constructs
  the grant (`view.rs:242`) and sets `unsafe_cleartext` (`view.rs:157`) from the same
  flag in two separate functions, and nothing requires them to agree. A frontend can
  construct a grant without reporting it. The function in core that renders claim
  values under a designation should return the set of paths it revealed or hashed, so
  the marker is an output of the reveal rather than a convention the frontend must
  remember. That also generalizes the marker from a boolean to a list of paths.
- **A debugger reads straight past it.** `credentialSubject.id` appears in cleartext in
  a CodeLLDB frame view. The guarantee covers `Display`, `Debug`, and `Serialize`, not
  memory.

### Why vcrd does not classify sensitivity

**Inference failed on the first real input.** The spike classified values by rule —
booleans and small integers, a list of known low-cardinality claim names, strings of
four characters or fewer — and hashed everything else. The first fixture run hashed a
birth date as though it were high-entropy, when its plausible value space is about
forty thousand entries; a fourth rule for date-like strings had to be added
(`redact.rs:175`). The name list also matches leaf names regardless of nesting, so the
structural field `degree.type` is treated as a claim called `type`.

**The standards offer no usable signal.** SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc-19`,
§5.6.4) defines per-claim `sd` metadata — `always`, `allowed`, or `never` — but that
states whether a holder may withhold a claim from a verifier, not whether a value may
appear in a log. The draft defines nothing for display or logging sensitivity, the
metadata is optional, and its default (`allowed`) conveys nothing. VCDM 2.0 has no
per-property sensitivity metadata.

**Per-type designations would be an unbounded curation burden.** Every credential type
would need a privacy judgment, and paths do not carry across formats — VC-JWT places
claims under `credentialSubject.*`, SD-JWT VC at top level, mDL in namespaces. Owning
those judgments indefinitely is a trust-evaluation responsibility of the kind §1 places
outside vcrd.

### Caller designation

- **The path you see is the path you type.** vcrd prints each masked claim with its
  path in the format's own notation, and a designation accepts exactly that string.
- **One structural rule per format, not a per-field catalog.** Each format defines which
  of its fields are claims (masked) and which are metadata (shown in full, per §8). The
  format module must draw that line anyway to populate `Document`.
- **The `credentialSubject.id` question disappears.** It is a claim, so it is masked
  unless designated.
- **A CI gate becomes a machine check.** Because the result lists every revealed or
  hashed path, a pipeline can reject any output in which anything was revealed.

This is an initial design. The path notation, multi-path matching, whether selective
reveals warn on stderr, scoping by credential type, and the hash construction all need
decisions informed by actual usage.

### Testing

The spike's only default-redaction test, `redaction_is_on_by_default_in_json`
(`vcrd-cli/tests/fixtures.rs:249`), covers JSON alone and checks for two specific
literals. Nothing tests `text` or `plain`. The design supports a stronger test: place a
unique canary string in every claim leaf, then for each of the three formats assert that
no canary reaches stdout or stderr by default, that exactly the designated canaries do,
and that all of them do under `--unsafe`. Because the expected set is computed from the
designations, the test remains correct as they change.

> **REQUIREMENTS change (applied)** — §8's redaction paragraph now requires masking every
> claim value by default, enforcement in `vcrd-core`, caller designation of paths to
> show, hash, or mask, and a result marker listing every reveal. §8's configuration
> paragraph now includes per-path redaction designations under the standard precedence,
> resolved per path. §16 item 18 records the questions that need usage data.

---

## 4. The `CredentialFormat` / `ProofSuite` seam

**Decision. The division of responsibility holds; the interface type is JOSE-specific.**
A format locates each proof and supplies key hints, key resolution happens in the
pipeline, and a suite verifies. What the spike did not establish is which side computes
the bytes a signature covers — and for Data Integrity it cannot be the format.

```rust
// vcrd-core/src/model.rs:258
pub struct ProofDescriptor {
    pub suite: SuiteId,
    pub declared_alg: String,
    pub key_hints: crate::keys::KeyHints,
    /// The bytes the signature is over, and the signature itself. This is the
    /// `CredentialFormat` -> `ProofSuite` seam (prototype question 4).
    pub signing_input: Vec<u8>,
    pub signature: Vec<u8>,
}
```

### What holds

**The format does not own verification, even when the JWS is the container.** The format
produces `signing_input` (`header.payload`) and `signature`; `JoseSuite` verifies them
without any knowledge of credentials.

**Key resolution belongs in neither trait.** It sits in the pipeline
(`vcrd-core/src/pipeline.rs:53`): the format supplies *hints* (`kid`, `iss`, embedded
`jwk`), the resolver applies policy, and the suite receives an already-resolved key
(`pipeline.rs:74`). If the format resolved keys it would be deciding what to trust, and
finding 6 is about why that is a bypass.

**Both traits are dyn-compatible**, confirmed by construction: the registry backing
`vcrd formats` / `vcrd suites` holds them as `Vec<Box<dyn CredentialFormat>>` and
`Vec<Box<dyn ProofSuite>>` (`vcrd-core/src/format.rs:50–51`). Dyn compatibility forbids
generic methods, associated constants, and methods returning `Self`; methods taking a
borrowed `ProofInput<'a>` are fine. Rust does permit associated types, but a trait
object must fix them (`dyn CredentialFormat<Output = X>`), so a registry holding formats
with different output types cannot use one. That is why per-format output is a closed
enum, `FormatDetail`, and why finding 1's `#[non_exhaustive]` decision applies to it.

### What does not generalize: who computes the signed bytes

The spike's interface has the format compute `signing_input`. For JOSE that is trivial —
the signed bytes are the literal `header.payload`. For JSON-LD Data Integrity, the
second committed format, the cryptosuite decides. In the W3C Recommendation
*Data Integrity EdDSA Cryptosuites v1.0* (15 May 2025), `eddsa-rdfc-2022` transforms the
document with RDF Dataset Canonicalization (§3.2.3) and `eddsa-jcs-2022` with the JSON
Canonicalization Scheme (§3.3.3); the verification input is the hash of the canonical
proof configuration concatenated with the hash of the canonical document.

A format therefore cannot produce the signed bytes without dispatching on cryptosuite
name, which would put suite logic in the format. In Parnas's terms, the design decision
"how the signed bytes are computed" belongs to the suite, so the suite must own the
transformation, and JOSE's transformation is the identity over `header.payload`. The
interface then has to carry what each kind of suite needs — detached bytes for JOSE, the
unsecured document and proof options for Data Integrity — which gives up the property
that a suite never sees credential content. If that makes `ProofInput` an enum, it
needs `#[non_exhaustive]` for the same reason `FormatDetail` does.

This reverses the goals document's expectation. JWT was expected to stress the seam and
Data Integrity to be obvious. For *where the proof is located* that is right; for
*computing the signed bytes*, JOSE is trivial and Data Integrity is the hard case. A
seam exercised by one format and one suite, paired one-to-one, cannot show that it
generalizes. **Open design point for ARCHITECTURE.md**, to be settled when the Data
Integrity path is designed.

### Two corrections to the interface

- **`ProofInput` should not carry key provenance.** It passes `provenance`
  (`format.rs:39`), and `JoseSuite` never reads it; the suite's only use of `Context` is
  the algorithm policy. Provenance is the pipeline's concern.
- **Key hints should be typed.** `KeyHints.embedded_jwk` is an
  `Option<serde_json::Value>` (`vcrd-core/src/keys.rs:53`), which the debugger cannot
  display (see "Answered as a side effect"). The format should parse the JWK into a
  typed structure at the parse boundary.

`ProofOutcome::Verified { disclosed: Option<DisclosureSet> }` is present so selective
disclosure is not designed *out*. Per the goals document, the spike makes no claim that
it is sufficient.

---

## 5. Can any JOSE crate meet §10?

**Decision. vcrd implements the JWS layer itself, directly over RustCrypto and dalek
primitives, rather than depending on a JOSE crate.** This closes §16 item 16.

Two reasons carry the decision:

1. **vcrd must own the policy layer regardless of which crate it uses** — the caller's
   algorithm allowlist, rejecting unsupported algorithms by name, binding the algorithm
   to a key type, and choosing the verifier. That layer ends in direct calls to the
   primitive crates' verifiers (`jws::verify_signature`,
   `vcrd-core/src/jws.rs:228`), which perform all hashing and arithmetic. A JOSE crate
   would sit between vcrd's own policy code and those primitives and supply nothing
   either side needs. This argument holds for any JOSE crate, not only the ones
   examined.
2. **The one candidate with ES512 coverage, josekit 0.10.3, is an OpenSSL FFI
   dependency with unstructured errors** (below). §6 penalizes FFI, and it closes off
   the WASM target §5 cites as a reason for choosing Rust.

The candidates on record are josekit (probed) and `jsonwebtoken` and `ssi-jwk` (§16's
existing notes: both stop at ES384). Reason 1 is what extends the decision beyond them.

The layer is 286 lines of `jws.rs`, excluding tests, and covers five algorithms. The
outcomes §10 requires are distinct values:

```rust
// vcrd-core/src/jws.rs:102
pub enum AlgRejection {
    /// `alg: none`. Never acceptable, never a policy question.
    None,
    /// vcrd cannot do this. Blame: vcrd.
    Unsupported { declared: String, supported: Vec<&'static str> },
    /// vcrd could, but the caller said no. Blame: policy.
    PolicyRejected { declared: String, allowed: Vec<String> },
}
```

```rust
// vcrd-core/src/jws.rs:218
pub enum SignatureCheck {
    Valid,
    Invalid,
    /// The resolved key cannot carry this algorithm. This is what catches
    /// "HMAC-signed with the issuer's public key".
    KeyTypeMismatch { key_kind: &'static str, expects: &'static str },
}
```

`select_algorithm` reads the declared algorithm from the header and checks it against
vcrd's supported set and the caller's allowlist; `verify_signature` then requires the
resolved key to be of the kind that algorithm uses. The header value can therefore only
resolve to an algorithm that policy permits and the key supports — it cannot widen the
set.

### What the josekit probe established

The adapter (`--features josekit-probe`, `vcrd-core/src/josekit_probe.rs`, 134 lines)
was built and its tests run:

```bash
cargo test -p vcrd-core --features josekit-probe josekit -- --nocapture
```

```
unsupported-alg -> UnsupportedByCallerCode { declared: "ES256K" }
allowlist       -> PolicyRejectedByCallerCode { declared: "ES256" }
es512 with a bogus key -> Rejected { error_type: "verifier", message: "Invalid key format: error:03000072:digital envelope routines:X509_PUBKEY_get0:decode error:crypto/x509/x_pubkey.c:466:" }
tampered        -> Rejected { error_type: "decode_with_verifier", message: "Invalid signature: The signature does not match." }
alg:none        -> UnsupportedByCallerCode { declared: "none" }
```

The probe never verified a token. Its tests use keys that cannot verify any fixture —
the RFC 8037 example Ed25519 key for every token (`josekit_probe.rs:109`), and a JWK with
empty coordinates for ES512 (`:129`) — so no run returns `Verified`, and the `tampered`
result would be the same for an untampered token. What it does establish is josekit's
API shape and error model:

- **josekit depends on OpenSSL through FFI** (`josekit-0.10.3/Cargo.toml:53`).
- **Errors are strings carrying OpenSSL internals**, as in the ES512 line above. §6
  requires structured, locale-independent results.
- **A verifier is constructed by naming a concrete algorithm constant**, and there is no
  allowlist concept, so the caller writes both the policy check and the
  unsupported-algorithm check. The probe's `UnsupportedByCallerCode` and
  `PolicyRejectedByCallerCode` outcomes are produced by the probe's own code before
  josekit is called.
- **`decode_header` returns `Box<dyn JoseHeader>`** (`josekit-0.10.3/src/jwt.rs:68`),
  with `alg` available only as an untyped claim.
- **josekit names ES512**, since the probe compiles against its `ES512` constant.

Two properties of josekit are sound and should not be held against it. It handles
unsigned tokens through a separate function, `decode_unsecured` (`jwt.rs:77`), so it does
not conflate `alg: none` with an unknown algorithm; the probe's `alg:none` result above
comes from the probe's own catch-all match arm (`josekit_probe.rs:88`). And
`deserialize_compact_with_selector` (`jws.rs:166`) takes a caller-written closure over the
header, so the caller — not the header — chooses the verifier, the same structure as
vcrd's `select_algorithm`.

Last release: 0.10.3, 2025-05-20.

### Decision: Ed25519 verification checks for weak keys and uses strict verification

**Decision.** Key resolution checks every Ed25519 key with `VerifyingKey::is_weak()` and
reports a small-order key as its own finding, and the EdDSA path calls `verify_strict`
instead of `Verifier::verify`. This goes into ARCHITECTURE.md alongside the algorithm
allowlist.

**Rationale.** vcrd's aim is to give the caller as much useful information as possible,
with an explicit warning wherever there is a security or trust risk. A weak key is such a
risk, and it should be named rather than folded into a generic signature failure.

**What the prototype does, and why it is insufficient.** The EdDSA path calls
`ed25519-dalek`'s `Verifier::verify` (`vcrd-core/src/jws.rs:238`). Both it and
`verify_strict` reject an out-of-range S (RFC 8032 §5.1.7; the `legacy_compatibility`
feature is off) and a non-canonical R encoding, and both check the cofactorless equation
[S]B = R + [k]A. Only `verify_strict` also rejects a small-order public key A or
signature point R (`ed25519-dalek-2.2.0/src/verifying.rs:370`).

- **Small-order A.** "A weak public key can be used to generate a signature that's valid
  for almost every message" (`verifying.rs:185`). With A the identity point, a signature
  with R = [S]B verifies for every message and needs no private key.
  `VerifyingKey::from_bytes` (`verifying.rs:165`) only decompresses the point, so the
  prototype's `did:key` decoding (`vcrd-core/src/keys.rs:384`) accepts such a key, and a
  credential under that DID would report *verified* with *independently resolved* key
  provenance — the false "verified" result §12's threat model names. It does not permit
  forgery under an honest issuer's key; it means a verified result no longer shows that
  anyone held a secret.
- **Small-order R.** Chalkias, Garillot, and Nikolaenko, *Taming the Many EdDSAs* (2020),
  found that widely used Ed25519 libraries disagree on such edge cases, which matters for
  §11's differential testing.

**Why both mechanisms.** `verify_strict` alone would reject a weak key, but report it only
as `signature_invalid`. Checking `is_weak()` during resolution produces a distinct
finding that names the problem, attributed to the input, and applies whatever the key's
source — `did:key`, a caller-supplied JWK, or an embedded JWK. `verify_strict` still
covers small-order R, which resolution never sees.

**Limits.** `verify_strict` does not switch to the cofactored equation, and
`is_small_order` does not reject a key that combines a prime-order point with a torsion
component.

**Tests that pin the decision.** Two adversarial fixtures, in §11's negative category:
a `did:key` encoding the identity point, which must produce the weak-key finding; and a
signature whose R is small-order under an ordinary key, which must fail verification.

### RustCrypto notes worth carrying forward

**Verification works for all five algorithms, ES512/P-521 included.** The §10 evidence
point about ES512 blocking interop is a story about JOSE wrappers, not about pure-Rust
primitives.

`p521` 0.13.3 is visibly the least-travelled path, and the spike hit three edges:

- `SigningKey::verifying_key()` is gated on a `verifying` feature the crate does not
  declare — the method cannot be called at all. `VerifyingKey::from(&sk)` is the route.
- `VerifyingKey` does not implement `Debug`, unlike its p256 sibling.
- No RFC 6979. `Signer` delegates to `RandomizedSigner` with `OsRng`, so P-521 signing
  is non-deterministic. Verification is unaffected; only fixture minting had to seed an
  RNG explicitly.

The spike pinned the 0.13 line to stay on one `elliptic-curve` generation with p256. A
0.14 line exists (released 2026-07-08) and may have addressed these; worth re-checking
when the real implementation starts.

> **REQUIREMENTS change (applied)** — §16 item 16 is struck through and marked resolved.
> §10's algorithm paragraph now states that vcrd implements the JWS layer directly over
> well-audited primitive crates; the reasoning stays here rather than in the
> requirements.

---

## 6. The key-provenance rule

**Decision. Key provenance is a required v1 result field, reported whether verification
succeeds or fails.** It states which key vcrd verified with and where that key came
from, and separately which key, if any, the credential offered and whether that key
verifies the signature. It carries no single trust boolean.

### Precedence

Highest first:

1. Caller-supplied key material, matched by `kid`, else the sole key.
2. A `did:key` in the issuer. The identifier encodes the key, so a credential cannot name
   this issuer while using a different key. Nothing establishes who controls the
   identifier.
3. An embedded `jwk`, **only** when its RFC 7638 thumbprint matches a key from 1 or 2.
4. An embedded `jwk` with an explicit caller opt-in — used, and reported as such.
5. Otherwise refused, and the refusal is a finding, not a silent fall-through to "no key
   material".

Key material from the caller or from the issuer identifier takes precedence over an
embedded key. `embedded-jwk.jwt` — an attacker's key in the header, self-consistently
signed, with a `did:key` issuer for a different key — resolves to the issuer
identifier's key and fails verification.

### Evidence that provenance must be in v1

```bash
for args in "fixtures/embedded-jwk.jwt" "fixtures/embedded-jwk-only.jwt" "fixtures/embedded-jwk-only.jwt --trust-embedded-key"; do printf '%-55s ' "verify $args"; ./target/debug/vcrd verify $args --now 2026-08-22T12:00:00Z --format json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
kp=[p['key_provenance'] for p in d['proofs']]
print('exit', d['exit_code'], '| codes', [f['code'] for f in d['findings']], '| provenance', [(k['kind'], k.get('accepted')) for k in kp])
"; done
```

```
verify fixtures/embedded-jwk.jwt                        exit 4 | codes ['key.embedded_ignored_independent_available', 'verify.signature_invalid'] | provenance []
verify fixtures/embedded-jwk-only.jwt                   exit 4 | codes ['key.embedded_untrusted'] | provenance []
verify fixtures/embedded-jwk-only.jwt --trust-embedded-key exit 0 | codes ['key.embedded_accepted_by_flag'] | provenance [('credential_supplied', True)]
```

With the opt-in, **the exit code is 0**. That is correct: the caller asked for it, and
verification succeeded under the policy they set; a non-zero code would make the opt-in
useless. But the exit code then cannot distinguish verification against key material
from the caller or the issuer identifier from verification against a key the credential
supplied about itself. Only provenance carries that. If it is not in v1, consumers built
in the meantime cannot tell the two apart, and adding it later does not fix them.

### The prototype drops provenance when verification fails

The two failed runs above report no provenance at all — including `embedded-jwk.jwt`,
where it matters most. `run_verify` keeps per-proof results only when every proof
verifies (`vcrd-core/src/pipeline.rs:88`); otherwise it returns `Stage::Failed
{ findings }` (`:98`), discarding the results and their provenance, and the CLI reads
proofs only from a passed phase (`vcrd-cli/src/view.rs:172–175`). Provenance must be
reported for failed verification too, which finding 1's decision that a failed tier
carries its output provides.

### Why no single trust boolean

Any single boolean mislabels at least one source:

- **"Independent of the credential"** is false for `did:key`, because the DID string
  comes from the credential's `issuer` field. It would then look the same as an embedded
  key, although `did:key` prevents key substitution and an embedded key does not. The
  prototype groups `did:key` with caller-supplied keys as `IndependentlyResolved`, whose
  doc comment — "established without trusting the credential's own contents"
  (`vcrd-core/src/keys.rs:97`) — does not hold for `did:key`.
- **"Bound to the issuer identifier"** is undefined for caller-supplied keys. vcrd does
  not check that such a key belongs to the issuer the credential names; that association
  is the caller's assertion.

Deciding which sources are acceptable is a trust judgment, which §1 leaves to the
software above vcrd.

### Structure

Proposed shape, shown for `embedded-jwk.jwt`:

```json
"key_provenance": {
  "source": "issuer_identifier",
  "method": "did:key",
  "thumbprint": "…",
  "credential_key": {
    "location": "header.jwk",
    "thumbprint": "…",
    "matched": false,
    "verifies_signature": true
  }
}
```

**`source`** — where the key vcrd verified with came from. Absent when no key was used.

| value | meaning | what it does *not* establish |
|---|---|---|
| `caller_supplied` | key material the caller passed in | anything beyond the caller's own assertion that it belongs to the issuer |
| `issuer_identifier` | derived from the issuer identifier the credential names (`did:key`); the credential cannot use a different key while naming this issuer | who controls that identifier |
| `credential_embedded` | a key the credential carries about itself, used only because the caller opted in | anything — it is bound to nothing |

`source` is an open enumeration. Network resolution of a DID and certificate chains
anchored to a caller-supplied root will add values with different guarantees, so
consumers must handle values they do not recognize — the same reasoning as
`#[non_exhaustive]` in finding 1.

**`credential_key`** — present whenever the credential offered a key, whether or not it
was used:

- `matched` — whether it is the key vcrd verified with.
- `verifies_signature` — whether the signature verifies under the offered key. vcrd
  performs this verification as additional information; it never affects the verdict or
  the exit code. It is subject to the same algorithm policy and key-type binding as the
  main verification, and absent when that verification cannot be attempted.
  `matched: false` with `verifies_signature: true` is specific evidence of key
  substitution: the credential was signed with a key that is not the issuer's.

| situation | `source` | `credential_key` |
|---|---|---|
| `did:key` issuer only | `issuer_identifier` | — |
| caller-supplied key set | `caller_supplied` | — |
| embedded key equals the `did:key` | `issuer_identifier` | `matched: true` |
| embedded key differs (`embedded-jwk.jwt`) | `issuer_identifier` | `matched: false`, `verifies_signature: true` |
| embedded only, caller opted in | `credential_embedded` | `matched: true` |
| embedded only, no opt-in | *(absent)* | `matched: false`; the refusal is the `key.embedded_untrusted` finding |

This structure needs no `accepted` flag, since `source: credential_embedded` occurs only
with the opt-in, and no separate variant for a pinned embedded key, which is
`matched: true`. The prototype's `EmbeddedPinnedToResolved` variant
(`vcrd-core/src/keys.rs:66`) is declared but never constructed.

### The `did:key` gap table

Decoding and verifying are separate capabilities, and the gap is reported by name with
`blame: vcrd`, not as a generic failure:

| Multicodec | Name | Decodes | Verifies |
|---|---|---|---|
| `0xed` | ed25519-pub | yes | yes |
| `0x1200` | p256-pub | yes | yes |
| `0x1201` | p384-pub | named only | no |
| `0x1202` | p521-pub | yes | yes |
| `0xe7` | secp256k1-pub | named only | no |
| `0x1205` | rsa-pub | named only | no |

The RSA control fixture is the practical consequence: it has no `did:key` route and
must resolve through `--jwks`. Keeping the "names vcrd knows" list wider than the "keys
vcrd can use" list is what lets an unsupported curve fail by name instead of as an
opaque decode error — the §10 principle, applied to key material rather than
algorithms.

> **Proposed REQUIREMENTS change** — §10's DID-resolution paragraph, or a new §12
> bullet, should state the precedence rules above and require key provenance in the v1
> result schema — reported for failed verification as well as successful, stating where
> the key used came from and any key the credential offered, including whether that key
> verifies the signature — on the same "retrofitting a load-bearing schema is
> disruptive" reasoning §10 already uses for the algorithm allowlist and the
> challenge/domain parameters.

---

## 7. What "validate" checks for VC-JWT — the `inspect` phase

**Answer.** The middle phase checks the unsecured credential against the requirements of
VCDM 2.0 and VC-JOSE-COSE that need no cryptography and no network, and checks the
validity period against the injected clock. It does not check the signature (`verify`)
or anything that requires resolution: context documents, schemas, status lists.

**Decision: the phases are `parse`, `inspect`, and `verify`**, and the CLI operations are
`inspect` (runs `parse` and `inspect`) and `verify` (runs all three). The name "validate"
is not used, because the standards in scope already give "validation" conflicting
meanings (below).

**Decision: implement VC-JOSE-COSE (VCDM 2.0).** The JWS payload *is* the credential, as
the goals document expected.

### What the prototype's middle phase checks

From `validate_jwt_vc` (`vcrd-core/src/validate.rs`). Structural checks — size, nesting
depth, JWS segments, base64, JSON, presence of `alg` — happen in `parse`.

| check | line | severity | basis |
|---|---|---|---|
| profile: VCDM 1.1 JWT mapping refused; unrecognized payload refused | :19, :51 | error | prototype's choice |
| header `typ` is `vc+jwt` or `application/vc+jwt` | :66 | warning | VC-JOSE-COSE §3.1.1: SHOULD be `vc+jwt` |
| `@context` present, first item `https://www.w3.org/ns/credentials/v2` | :77 | error | VCDM 2.0 §4.3, MUST |
| `type` includes `VerifiableCredential` | :90 | error | VCDM 2.0 requires `type`; `VerifiableCredential` comes from its type table, not a normative sentence |
| `issuer` present | :98 | error | VCDM 2.0 §4.7, MUST |
| `credentialSubject` present | :101 | error | VCDM 2.0 §4.8, MUST |
| `validFrom` / `validUntil` parse, and are current against the clock and skew | :105 | error | format: VCDM 2.0 §4.9, MUST; currency: VCDM leaves the response to the verifier |

Requirements these checks miss are listed under "Development practice" below, as the
first inputs to the review cycle.

### Registered JWT claims

VC-JOSE-COSE §3.1.3 gives the registered claims specific meanings rather than making them
irrelevant:

- `iat` and `exp` are the issuance and expiration times of the *signature*, distinct from
  `validFrom` and `validUntil`. An expired `exp` is a fact about the securing mechanism,
  so it belongs to `verify`. The prototype ignores it.
- Issuers SHOULD avoid conflicting values between `iss`/`issuer`, `jti`/`id`, and
  `sub`/`credentialSubject.id`. A conflict is reportable as a warning. The prototype does
  not report it.
- The claim names `vc` and `vp` MUST NOT be present, which is why a payload carrying `vc`
  cannot be VC-JOSE-COSE and is detected as the VCDM 1.1 mapping instead.

The VCDM 1.1 JWT mapping is detected, named, and refused with `blame: vcrd` — the
credential may be legitimate, and vcrd does not implement that profile — and the concrete
disagreement between its duplicated claims is reported alongside:

```bash
./target/debug/vcrd verify fixtures/vcdm11-mapping.jwt --now 2026-08-22T12:00:00Z --format json 2>/dev/null | python3 -c "
import json,sys
for f in json.load(sys.stdin)['findings']: print(f['code'], f['blame'], json.dumps(f['detail'], sort_keys=True))
"
```

```
validate.profile_not_implemented vcrd {"detected": "vcdm-1.1-jwt-mapping", "implemented": "vc-jose-cose", "marker": "payload.vc", "type": "profile_not_implemented"}
validate.claim_disagreement input {"jwt_claim": "exp", "jwt_value": "1893456000", "type": "claim_disagreement", "vc_field": "expirationDate", "vc_value": "2035-01-01T00:00:00Z"}
```

Naming the profile is better than guessing which duplicated claim is authoritative. If
1.1 support is ever added, the authority rule is written down here.

### Why not "validate"

VCDM 2.0 §2 defines *verification* as evaluating whether a credential is authentic and
current as a statement by its issuer, and *validation* as assurance that a claim meets a
verifier's business requirements for a particular use. The standard's validation is what
REQUIREMENTS §4 calls trust evaluation, which vcrd excludes. Other standards in scope use
the word differently again: RFC 7515 §5.2 for checking a JWS signature or MAC, RFC 5280
§6 for certification path checking, and Data Integrity 1.0 for context checks. vcrd
therefore does not use the term.

Under the phase rule, running `verify` also runs `inspect`, which includes the validity
period, so the `verify` operation covers what VCDM 2.0 calls verification. The name
`prove` was rejected because the standards use proving for *producing* a proof: Data
Integrity 1.0 defines proof generation (`Add Proof`) and proof verification
(`Verify Proof`), and the BBS signatures draft (`draft-irtf-cfrg-bbs-signatures-10`) has
a Prover that runs `ProofGen`, with checking done by `ProofVerify`.

### Temporal checks belong in `inspect`

**This produced the single most useful result in the spike.** `expired.jwt` reports the
middle phase failed *and* `verify` passed: expired, and correctly signed, as two separate
facts. Had `validUntil` been checked in `verify`, that credential would collapse to one
verification failure, and the caller would lose the knowledge that the issuer's signature
is sound — exactly what distinguishes a stale credential from a forged one.

### When an `inspect` failure blocks `verify`

**Decision.** The phases run in order, and each CLI operation runs every phase up to its
own. A `parse` failure blocks both later phases. When `verify` is requested, an `inspect`
failure blocks it **only if the failure shows that verification would be impossible or
dangerous**:

- **Impossible** — the materials for checking the proof are not available.
- **Dangerous** — verifying could expose vcrd to an internal exploit, or would require
  fetching external information, such as cryptographic material, from a suspicious
  source.

Any other `inspect` failure is reported, and `verify` still runs. On the JWT path, none
of the prototype's middle-phase failures blocks verification, because the signature
covers the token's bytes whatever the payload says:

```bash
for f in expired.jwt vcdm11-mapping.jwt; do printf '%-20s ' "$f"; ./target/debug/vcrd verify fixtures/$f --now 2026-08-22T12:00:00Z --format json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print({k:v['status'] for k,v in d['stages'].items()}, [p['outcome'] for p in d['proofs']])
"; done
```

```
expired.jwt          {'parse': 'passed', 'validate': 'failed', 'verify': 'passed'} ['verified']
vcdm11-mapping.jwt   {'parse': 'passed', 'validate': 'failed', 'verify': 'passed'} ['verified']
```

Illustrative cases, none of which the prototype implements:

- **Impossible:** a Data Integrity credential with no `proof` object, or a proof missing
  the value or verification method it needs.
- **Dangerous, internal:** input that would push a `verify` step past a limit it depends
  on, such as an RDF graph that exceeds the canonicalization budget §6 describes.
- **Dangerous, external:** a JWS header that tells the verifier where to fetch keys —
  `jku` (RFC 7515 §4.1.2) or `x5u` (§4.1.5) — or an issuer identifier whose resolution
  would reach a private, loopback, or link-local address (§12), or an `@context` outside
  the pinned set (§12).

Open details, to settle when the first such case is implemented:

- **Blocks must be reported, not silent.** When `verify` is `NotReached` because of
  `inspect`, the result has to identify the findings that caused it and whether the
  reason was impossibility or danger.
- **Impossibility can depend on the caller.** A credential without a usable issuer
  identifier is unverifiable only if the caller also supplied no key material, so
  classification cannot always be a fixed property of a finding code.
- **Danger is not always non-conformance.** A conforming token can carry `jku`. For it to
  block `verify` under this rule, `inspect` must report it as a failure, which also
  changes the result of `vcrd inspect` alone.

The exit-code consequence should be documented rather than smoothed over: an expired but
correctly signed credential exits with the middle phase's code (3 in the prototype), not
the verification code. A script branching only on verification failure will miss expiry;
scripts that care should read the per-phase results.

### Clock skew — §16 item 17

**Default zero, configurable.** A credential 30 seconds past expiry fails at skew 0 and
passes at 60:

```bash
for s in 0 60; do printf 'skew %-3s ' "$s"; ./target/debug/vcrd verify fixtures/expired.jwt --now 2020-01-01T00:00:30Z --skew-seconds $s --format json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d['stages']['validate']['status'], [f['code'] for f in d['findings']])
"; done
```

```
skew 0   failed ['validate.expired']
skew 60  passed []
```

The argument for zero: a non-zero default silently accepts expired credentials, and
§1's "vcrd reports facts, judgment lives elsewhere" stance says leniency is the
caller's call. A verifier that needs tolerance for clock drift knows it does; one that
does not should not inherit it invisibly. The counter-argument — that every real
deployment ends up wanting 30–60 seconds — is real, and the answer is that they can set
it in one place via the §8 config file.

> **Proposed REQUIREMENTS change** — §16 item 17 is closed. §4 should name the phases
> `parse`, `inspect`, and `verify`, state that `inspect` includes validity-period checks,
> and state that an `inspect` failure blocks `verify` only when verification would be
> impossible or dangerous. §8's `inspect` description changes accordingly, and its
> sentence about there being no separate `validate` subcommand is removed.

---

## Answered as a side effect

**Injection ergonomics.** Nine injected things (clock, algorithm policy, key store,
limits, skew, embedded-key opt-in, expected challenge, expected domain, redaction
policy). One `Context` struct with a builder, taking the clock positionally because it
has no default: `Context::builder(clock).alg_policy(p).keys(k).build()`. This was
comfortable at nine and shows no sign of straining. No reason to split it. Finding 3's
per-path redaction designations will add to the count without changing that.

**No default clock is the right call and cheap.** `SystemClock` sits behind a
`std-clock` feature that core does not enable and `vcrd-cli` does. Built without it,
`--now` is mandatory and the error says exactly why. The property "core never calls
`SystemTime::now()`" holds for the default build rather than by convention.

**`serde_json` has a fixed recursion limit of 128** (`serde_json/src/de.rs:63`,
`remaining_depth: 128`), proven by test — 200 levels rejected, 100 accepted — and its
public API only lets you *disable* it, not lower it. A caller-configurable cap needs its
own mechanism, and a string-aware byte-level prescan supplies one in about 30 lines.

**A limit must run before the work it bounds, and in the prototype it does not.**
`JwtVcFormat::parse` calls `jws::parse_compact` first (`vcrd-core/src/jwt_vc.rs:75`),
which base64-decodes both segments and parses both into `serde_json::Value`
(`vcrd-core/src/jws.rs:193`, `:195`). Only then does it call `measure_depth`
(`jwt_vc.rs:110`). So vcrd's configurable cap — 32 by default — bounds nothing: a
128-level payload is fully decoded and parsed before the cap is consulted, and what
actually bounds the work is serde_json's fixed limit. The cap is a report, not a
control. Enforcing size and depth on the encoded bytes before decoding, or parsing
through a depth-limited deserializer, is what §6 asks for.

**Measured limits.** From `vcrd measure fixtures/*.jwt`: realistic VC-JWTs are
825–1,156 bytes in total, with 557–684 byte payloads, at nesting depth 3 (4 for the 1.1
mapping). Against defaults of 256 KiB and depth 32, that is enormous headroom.

**The depth reported in the result is not the depth that was measured.**
`input.measured_depth` is 0 for every JWT, because `summarize` measures the *encoded*
token (`vcrd-core/src/pipeline.rs`), which is base64 and contains no structural
characters. The number that matters is the depth of the decoded payload, which
`vcrd measure` computes correctly. An output field that is silently meaningless in every
run is the kind of defect the development practice below exists to catch.

> **Caveat worth putting in the requirements.** Fourteen hand-authored fixtures are not
> a corpus. The *method* §6 asks for is settled — `vcrd measure` exists and works — but
> these numbers should not be treated as the derivation. SD-JWT disclosure arrays and
> JSON-LD contexts will move both figures, and the real defaults should wait for
> credentials nobody on this project wrote.

**Exit-code taxonomy.** Implemented as: blame outranks tier, because "vcrd cannot do
this" and "your policy said no" are different kinds of answer from "the credential is
bad".

| Code | Meaning |
|---|---|
| 0 | every attempted tier passed |
| 1 | caller error (unreadable input, bad flag) |
| 2 | parse failed |
| 3 | inspect failed (the prototype's validate phase) |
| 4 | verify failed |
| 5 | rejected by caller policy |
| 6 | not supported by vcrd |

Three consequences, documented rather than fixed, because they are inherent to
compressing a graduated result into one integer:

- An expired but correctly signed credential exits 3.
- A credential that is both unsupported *and* allowlist-rejected exits 6, while still
  reporting both findings.
- **The phase codes are not what a script gets when attribution is not the input's.**
  `vcdm11-mapping.jwt` fails the middle phase and exits **6**, not 3, because the
  finding is attributed to vcrd. So "3 means the middle phase failed" is false in
  general; the rule is that attribution outranks phase.

> **Proposed REQUIREMENTS change** — §8 says distinct exit codes distinguish parse,
> validation and verification failure. That is incomplete: the rule is that attribution
> outranks phase, so a failure attributed to vcrd or to caller policy takes its own code
> whichever phase produced it. §6's structural-limits bullet should also say that size
> and depth limits are enforced before the input is decoded and parsed, not after.

**`--verbosity 0`** prints nothing and returns the code. With partial success that
means the exit code is the *entire* answer, and it cannot express "expired but
correctly signed". That is an acceptable contract for the "I only care whether it
passed" use case §8 describes, provided the docs say so.

**Feature gates found a real diagnosability defect.** With no formats compiled in,
`parse.no_format_matched` attributed the failure to the *input*, sending a caller to
debug data that was fine when the build was at fault.

The decision that follows is a build-time rule plus a runtime rule, not a wider
feature-combination matrix:

- **`vcrd-cli` must fail to build with no format enabled** (`compile_error!`). A `vcrd`
  binary that cannot read any credential cannot do its job, and a build-time error is a
  better answer than a runtime finding.
- **`vcrd-core` may build with none.** §7 anticipates format implementations shipping
  from outside this repository, and a consumer registering their own
  `CredentialFormat` is a real case.
- **Attribution keys on the registry being empty at runtime, not on Cargo features.**
  An empty registry is the build's or the caller's fault; a non-empty registry that
  matches nothing is the input's. That rule stays correct when formats arrive from a
  third-party crate.

Building the feature combinations belongs in the real project's CI rather than in a
finding about throwaway code.

**The no-panic lint policy costs nothing.** `unwrap_used`, `expect_used`, and
`indexing_slicing` produce **zero hits** across `vcrd-core`, including every
untrusted-input path and the tests:

```bash
cargo clippy -q -p vcrd-core --all-targets 2>&1 | grep -c "^warning"
```

```
0
```

The lints were confirmed to fire, rather than being silently unconfigured, by adding a
function that calls `unwrap()` on an `Option` to a copy of the workspace and rerunning
clippy, which then reported `unwrap_used`. If parsers return `Result` from the start,
§6's rule is free — it is only expensive to retrofit.

**Debuggability is a design input, and it has a hard toolchain dependency on macOS.**
Rust ships its LLDB data formatters as Python in the toolchain sysroot
(`lib/rustlib/etc/lldb_lookup.py`). Driven by Apple's `/usr/bin/lldb` — which is what
`rust-lldb` falls back to, since no rustup component supplies an lldb —
`StdStringSummaryProvider` computes a bad address for any `String` reached through
nesting, raises, and **wedges the session**. `frame variable -D 1 *report` hangs on
`report->parse` and never returns.

CodeLLDB (`vadimcn.vscode-lldb`) loads those same Python formatters but drives them
with its own newer LLDB, and renders the whole `Report` correctly. It is opt-in:
`"sourceLanguages": ["rust"]` in the launch configuration, without which the formatters
never load and enums display as raw `$variants$`. Homebrew's LLVM is not an
alternative — same formatters, plus an unsigned `debugserver`. With Apple's toolchain
only, the fallback is `type category disable Rust` and reading discriminants raw.

**A `serde_json::Value::Object` is opaque under the debugger, whichever backing store
it uses.** Measured both ways on `KeyHints.embedded_jwk`, the one object reachable from
a `Report`:

| `preserve_order` | backing | rendering |
|---|---|---|
| on | `IndexMap` | `Object({map:{core:{indices:{raw:{table:{bucket_mask:3, ctrl:...` |
| off | `BTreeMap` | `Object({map:{root:Some({height:0, node:{pointer:0x...}}), length:3, ...` |

Neither shows a key or a value at any depth. Rust's formatters have no summary provider
for `serde_json::Map`. Scalars are unaffected — `flatten_claims` reduces claims to
leaves, so `ClaimValue` always holds a string, number, or bool and prints correctly.

The design consequence runs opposite to what one might assume: since raw `Value` is
un-inspectable, long-lived structures should hold *typed* data rather than `Value`.
`KeyHints.embedded_jwk` being an `Option<Value>` is the one place the spike got this
wrong; parsing a JWK into a struct at the parse boundary would have cost nothing and
made the key-provenance path legible.

`preserve_order` stays off, but on wire-contract grounds rather than debugging ones:
the JSON envelope's field order comes from `#[derive(Serialize)]` declaration order,
not from `Value`, so the only observable difference is key order within `detail`
sub-objects built by `json!` — and alphabetical is the more stable choice, since
insertion order silently changes whenever someone reorders a literal.

A caution the spike earned the hard way: a debugger is an instrument, and a finding
observed through an unvalidated one is not evidence. Verify the tooling before
trusting what it shows.

---

## Development practice: review against the standards at every milestone

**Decision.** At the end of each development milestone, the implementation is reviewed
against the normative text — the MUST, SHOULD, and MAY statements — of every standard it
implements. Each gap the review finds goes through four steps:

1. Write a test asserting the behavior the standard requires, citing the section.
2. Run it and confirm that it fails against the current code.
3. Fix the code.
4. Rerun the test and confirm that it passes.

**Why the test must first be seen to fail.** A test that has never failed has not shown
that it detects the gap it names; it can pass for reasons unrelated to the requirement.
The josekit probe in finding 5 is an example: its tests passed while exercising the
probe's own control flow, never the library behavior they appeared to test.

**Why the review is needed.** The checks in the prototype's `validate.rs` were not compared with
the specifications' text when they were written — the comment at
`vcrd-core/src/validate.rs:65` says VC-JOSE-COSE "requires" the `typ` header, where
§3.1.1 says it SHOULD be `vc+jwt`. Reviewing afterward against VCDM 2.0 and VC-JOSE-COSE
(both W3C Recommendations, 15 May 2025) found requirements no check covers:

- `validUntil` must be the same as or later than `validFrom` (VCDM 2.0 §4.9). Not
  checked.
- `issuer` must be a URL or an object whose `id` is a URL (VCDM 2.0 §4.7). Only presence
  is checked.
- A credential must contain `credentialSubject` (VCDM 2.0 §4.8). Presence is checked by
  counting leaf claims (`validate.rs:101`), so an empty `credentialSubject` object is
  reported as missing.
- JWT `iat` and `exp` are the issuance and expiration times of the signature, distinct
  from `validFrom` and `validUntil` (VC-JOSE-COSE §3.1.3). Ignored.
- Issuers should avoid conflicting values between `iss`/`issuer`, `jti`/`id`, and
  `sub`/`credentialSubject.id` (VC-JOSE-COSE §3.1.3). Conflicts are not reported.

These are the first inputs to the practice. The prototype will be deleted, so the tests
are written against the real implementation.

The review also covers terminology: when a standard enters scope, its definitions are
compared with vcrd's glossary, so that conflicting uses of a term are recorded rather than
discovered later.

> **Proposed REQUIREMENTS change** — §11 should state this practice as part of the
> testing strategy: at the end of each development milestone, review the implementation
> against the normative text of the standards it implements; each gap becomes a test that
> is observed to fail before the fix and to pass after it.

---

## <a id="16-disposition"></a>Disposition

Where each decision goes. "Applied" means the edit is already in the copy of
REQUIREMENTS.md kept beside this document.

### §16 items closed

- **Item 16 — JOSE dependency.** No JOSE dependency; vcrd implements the JWS layer
  directly (finding 5). *Applied.*
- **Item 17 — clock-skew tolerance.** Zero by default, configurable (finding 7).
  *Applied.*

### REQUIREMENTS changes

*Applied:*

- **§8 redaction.** Every claim value masked by default, enforcement in `vcrd-core`,
  caller designation of paths to show, hash, or mask, and a result marker listing every
  reveal (finding 3).
- **§8 configuration file.** Per-path redaction designations and the clock-skew
  tolerance, under the standard precedence, resolved per path (findings 3, 7).
- **§10 algorithms.** vcrd implements the JWS layer over audited primitive crates
  (finding 5).
- **§16 item 18.** Redaction path designation needs refinement from actual usage.

*Proposed:*

- **§4 phases.** Rename the tiers to phases, name them `parse`, `inspect`, `verify`,
  state that `inspect` includes validity-period checks, and state that an `inspect`
  failure blocks `verify` only when verification would be impossible or dangerous
  (findings 1, 7).
- **§6 structural limits.** Size and depth limits are enforced before the input is
  decoded and parsed, not after (side effects).
- **§6 graduated success and diagnosability.** Name the per-phase outcomes — not
  requested, not reached, failed with its output, passed — the accumulate-don't-collapse
  rule, and an attribution field as the mechanism for "whose side it's on" (finding 1).
- **§8 exit codes.** Attribution outranks phase: a failure attributed to vcrd or to
  caller policy takes its own code whichever phase produced it (side effects).
- **§8 `inspect`.** Update its description for the phase model and remove the sentence
  about there being no separate `validate` subcommand (finding 7).
- **§9 output.** A versioned schema owned by the frontend; core types are not
  serializable; one JSON document is emitted for every outcome including tool-level
  failure; the version stays at 0 until the schema is declared stable (finding 2).
- **§10 or §12 key provenance.** The precedence rules, and provenance as a required v1
  result field reported on failure as well as success (finding 6).
- **§11 testing.** The milestone review against the standards' normative text, with each
  gap becoming a test observed to fail before the fix and to pass after (development
  practice).
- **§13 CI.** Build the feature combinations in CI (side effects).

### New §16 open items

- **Added:** item 18, redaction path designation (above).
- **Proposed:** structural-limit defaults need a corpus of credentials nobody on this
  project wrote, not this spike's fixtures.
- **Proposed:** the blocking rule's details — how a block is reported, that
  impossibility can depend on caller-supplied key material, and that a dangerous
  condition is not always non-conformance (finding 7).

### Decisions for ARCHITECTURE.md

- **Result structure.** `Report` by value; `Result` reserved for caller faults; a
  four-variant per-phase outcome (`NotRequested`, `NotReached`, `Failed`, `Passed`);
  findings accumulate; a failed phase carries the output it produced; `#[non_exhaustive]`
  on format-specific enums; `Tier` becomes `Phase`, `blame` becomes `attribution`
  (finding 1).
- **Output boundary.** Core derives `Serialize` on nothing; the CLI owns the view model
  and the schema; absent keys are omitted today, with null-versus-omit still open
  (finding 2).
- **Redaction mechanism.** The `ClaimValue` newtype, hand-written `Debug`, and the
  capability token; the reveal marker produced by core rather than by frontend
  convention; the canary test across all three output formats (finding 3).
- **Format and suite boundary.** The division of responsibility holds; who computes the
  signed bytes must move to the suite for Data Integrity; key provenance leaves
  `ProofInput`; key hints become typed (finding 4).
- **Ed25519 verification.** `is_weak()` at key resolution as its own finding, plus
  `verify_strict`; two adversarial fixtures pin it (finding 5).
- **Key provenance shape.** `source` as an open enumeration, `credential_key` with
  `matched` and `verifies_signature`, and no trust boolean (finding 6).
- **Feature gates.** `vcrd-cli` fails to build with no format; `vcrd-core` may build with
  none; attribution keys on an empty registry at runtime (side effects).
- **Defects worth carrying.** Limits applied after parsing rather than before, and
  `input.measured_depth` measuring the encoded token (side effects).

Note when drafting: crate names stay out of requirements prose outside §3 and §16's
existing data-point style.

---

## Deliberately not answered

Per the goals document's own scoping: whether `ProofSuite` truly accommodates selective
disclosure (a second probe at SD-JWT's disclosure array would say far more than
anything JWT-only can), anything about RDF canonicalization or JSON-LD, whether the
differential oracles agree, and the whole OpenID4VP/live-verifier surface.

One additional gap the spike opened rather than closed: the `Document` projection was
sufficient for VC-JWT, but SD-JWT needs a notion of *withheld* claims — a claim that
exists and was not disclosed is neither present nor absent. Whether that fits
`Document` or forces a third state on `Claim` is the first thing the SD-JWT probe
should look at.

# vcrd Requirements & Design Document

## 1. Vision & Goals

vcrd is a tool for reading — and, over time, validating, verifying, and eventually
creating/editing — verifiable credentials (VCs). The long-term ambition is broad,
growing support for the many credential formats and proof types in use across the
identity ecosystem, built up the way mature domain tools accumulate breadth: through
sustained investment and, ideally, community contribution rather than one person doing
all of the work indefinitely.

Goals:

- **Coding/code-aware agents are the primary design lens — without degrading the experience for humans.**
  vcrd is designed foremost for unsupervised, scripted callers: CI pipelines and coding
  agents that need stable, structured output and no interactive prompts (§6). This shapes
  priorities — diagnosability and non-interactive-by-default come ahead of other, competing
  concerns (§6) — without making human usability secondary or provisional. A novice still
  gets useful, safe-by-default behavior with no flags; an expert can still script and
  compose vcrd tightly; and human-readable output stays a fully-supported, first-class
  format (§9).
- **Well documented.** Documentation is treated as a first-class deliverable, not an
  afterthought — see §13.
- **Free and open source**, licensed to make both use and contribution as unencumbered as
  possible — see §5.
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
credentials that already exist. Creating and editing them is a later phase (§10).

The dominant data model is the [**W3C Verifiable Credentials Data Model**](https://www.w3.org/TR/vc-overview/) (versions [1.1](https://www.w3.org/TR/vc-data-model-1.1/) and
[2.0](https://www.w3.org/TR/vc-data-model-2.0/)), which describes a credential as a JSON(-LD) document containing claims plus
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

Credentials are typically not submitted to a verifier individually and bare. Instead, a
holder assembles one or more credentials into a **Verifiable Presentation (VP)** — itself
a data model object defined alongside the credential itself, wrapping the included
credential(s) (potentially after selectively disclosing only some of their claims) and
typically carrying its own proof, separate from any credential's issuer proof, that binds
the presentation to the holder and demonstrates they actually control it rather than
merely holding a copy of someone else's credential. vcrd needs to be able to handle
presentations as well as bare credentials: inspecting, validating, and verifying a
presentation means checking its own holder-proof in addition to the proof(s) on each
credential it contains.

Credentials reference issuer and subject identities, typically via **Decentralized
Identifiers (DIDs)**. Resolving a DID to usable key material is either self-contained (no
network needed — e.g. `did:key`, or a JWK embedded directly in the credential) or requires
a network lookup (e.g. `did:web`). This distinction matters a great deal for vcrd, because
of the no-network-by-default principle in §6.

## 3. Related Work

vcrd builds on and seeks to complement a decade of work already done in this space. This
section surveys the tools and libraries closest to vcrd's own scope, based on direct
experience using each one rather than secondhand claims, and describes what each
contributes to the ecosystem vcrd is joining. It is not offered as a scorecard: vcrd's own design choices are
stated on their own terms throughout this document, starting with §6, rather than as a
point-by-point comparison with related work.

**A gap left by a departing generation of tools.** The most direct precedent for vcrd's own
shape — a small, scriptable command-line inspector for verifiable credentials — is
[didkit](https://github.com/spruceid/didkit), built by SpruceID. didkit performed valuable
work: issuing, verifying, and presenting W3C VCs across multiple proof formats from a
single Rust binary. It was archived in July 2025 as SpruceID's own engineering focus
shifted toward its mobile driver's license (mDL) product line — a natural consequence of a
company aligning its open-source investment with its business. Anyone with didkit in a script or
CI pipeline today will eventually need a replacement, and vcrd is built with that gap in mind.
Digital Bazaar's [vc-js-cli](https://github.com/digitalbazaar/vc-js-cli) played a similar
role a generation earlier for JSON-LD credentials specifically; its choice to bundle common
JSON-LD `@context` documents locally rather than fetch them live is a precedent vcrd's own
offline-by-default design continues, even though the tool itself has seen no functional
changes since 2019. Commercial vendors have now stepped back from this kind of tool twice.
vcrd's answer to that pattern is structural rather than promised: a not-for-profit,
community-maintained project has no revenue line to defund, so its continuity doesn't
depend on staying inside any one company's product roadmap.

**Libraries vcrd tests against, not on.** [ssi](https://github.com/spruceid/ssi)
(SpruceID), [isomdl](https://github.com/spruceid/isomdl) (SpruceID, ISO 18013-5/mdoc), and
[openid4vp](https://github.com/spruceid/openid4vp) (SpruceID) are active, well-built Rust
implementations of the kind of specifications that underlie vcrd: ssi's modular sub-crates
cover DID methods and VC data models broadly; isomdl is a working mdoc implementation that
ships its own conformance fixtures; openid4vp includes a reference wallet
and verifier useful for conformance testing. vcrd's own dependency
policy (§6) treats libraries like these as a resource to validate against rather than a
foundation to build on: interoperability is demonstrated through differential testing
against existing implementations, keeping vcrd's own trust surface small and independent of any
other maintainers' roadmaps. The reasoning behind that choice is written into §6, not
repeated here.

**Agent frameworks, a different layer.** [Credo-TS](https://github.com/openwallet-foundation/credo-ts)
(OpenWallet Foundation, TypeScript) and [Veramo](https://github.com/decentralized-identity/veramo)
(originally uPort, relaunched under ConsenSys Mesh, now stewarded by the Decentralized
Identity Foundation) are full agent frameworks: they build issuer, holder, and verifier
agents complete with DIDComm messaging, plugin architectures, and support for many DID
methods beyond the W3C-VC-centric ones vcrd targets — Veramo's `did:ethr` and EIP-712
support, for instance, reflect Ethereum-ecosystem breadth outside vcrd's scope.
Credo-TS is under active development with a broad plugin ecosystem; Veramo's day-to-day
maintenance today rests substantially on one developer's continued effort, a constraint worth
naming plainly since contributor capacity is exactly what this document's own community
strategy (§14) is written to take seriously. vcrd is solving a narrower problem
than either: not standing up an agent, but answering one question about one credential from
a single invocation — a shape aimed at scripts, CI pipelines, and coding agents that need a
fast, structured answer without adopting an agent runtime.

**Full-service platforms.** [walt.id](https://github.com/walt-id/waltid-identity) and the
EU Digital Identity Wallet program's
[verifier-endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint)
reference implementation are among the most complete tools in this space. walt.id's
open community stack covers issuance and verification across JWT, SD-JWT, and mdoc
credentials via OpenID4VCI/OpenID4VP, with a useful portal UI for manual testing;
a separate paid enterprise tier funds its ongoing development. The EUDI verifier-endpoint, a
Kotlin/Spring Boot service built for the EU's wallet reference-implementation program, pairs
careful spec-accurate validation with standout diagnostic output — named, structured error
codes once a request reaches validation logic, plus a full timestamped, actor-attributed
audit trail. Both have served as differential-testing partners for vcrd's protocol-level
work (§11), confirming that approach is workable in practice, not just in theory. vcrd aims
to be the minimal, embeddable, scriptable counterpart to platforms like these: something
that runs from a single command or library call, with no server to stand up, for the cases
where a full platform is more than what's needed.

**A different proof paradigm, ahead of vcrd's own roadmap.**
[anoncreds-rs](https://github.com/hyperledger/anoncreds-rs) (Hyperledger) is the reference
Rust implementation of the AnonCreds specification, a privacy-preserving credential scheme
predating and distinct from the W3C Data Model's Data Integrity/VC-JWT proofs. It supports
selective disclosure and predicate proofs (e.g. proving "over 18" without revealing a birth
date) and ships a bridge that converts AnonCreds credentials to and from W3C VC Data Model
JSON. This is exactly the proof shape named in §10's AnonCreds/BBS+ roadmap item, and it's
why the `ProofSuite` trait (§7) is being designed from the outset with room for
partial/selective-disclosure proofs, rather than retrofitted once a simple signature-check
assumption is already load-bearing. [ACA-Py](https://github.com/openwallet-foundation/acapy),
the long-standing reference agent implementation for the Aries/AnonCreds ecosystem, is the
natural place to look for a vcrd-style CLI already built on anoncreds-rs — but it's a full DIDComm
agent framework with a controller/admin-API architecture — the same shape difference already
true of Credo-TS and Veramo above — not a thin single-binary inspector. No lightweight tool
like that exists yet for this proof paradigm: a plausible future direction once vcrd's own
AnonCreds/BBS+ roadmap item (§10) is reached.

**Also considered.** Two further projects are deliberately out of scope here, not
overlooked: TBD (Block)'s `ssi-sdk`/web5 stack, a fourth independently-backed
implementation distinct from every lineage discussed above, and the official W3C VC Data
Model/VC-JOSE-COSE and OpenID Foundation conformance test suites — both candidates for
future differential-testing oracles once vcrd has enough surface area to test against them.
It's also worth noting three further Rust projects show this is an active community:
IOTA identity, indy-vdr, and Aries `vcx` are all active, non-archived
projects with recent commits. They solve different problems than vcrd does — a ledger-tied
library with no CLI of its own, a ledger-client proxy rather than a VC tool, and a full
pre-1.0 agent framework, respectively — not a gap in maintenance, just a gap in shape.

## 4. Operational Tiers

vcrd distinguishes four tiers of operation, each with different guarantees and different
network/trust implications:

1. **Parse** — is this input syntactically a credential in a format vcrd understands
   (valid JSON-LD/JWT/CBOR structure, etc.)? No semantic checking. This default operation
   can provide useful information to the user.
2. **Validate** — does the parsed structure conform to the relevant data model (required
   fields present, dates well-formed, `@context`/schema correct)? No cryptography
   involved, no network required — always available, always fast. This remains a
   distinct `vcrd-core` capability, but the CLI's `inspect` verb (§8) always runs it
   immediately after a successful parse rather than exposing it as its own subcommand —
   validating something that failed to parse isn't a meaningful operation on its own.
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

"Read-only, no-network by default" (§6) means: parse and validate are always available.
Verify is available offline only for self-contained key material; network-dependent
verification requires an explicit opt-in.

## 5. Language, Licensing, Naming & IP Policy

**Language: Rust.** Chosen because it lets the no-network-by-default and read-only-by-default
principles be enforced structurally (a capability like network access can be made
impossible to reach without being deliberately threaded through), because it produces a
single distributable binary (no runtime dependency for end users), because it has a clear
path to WASM for a future browser-extension frontend, and because a meaningful and
growing share of cryptographic and identity-ecosystem work — including exactly the
BBS+/Bulletproofs territory vcrd is interested in — is happening in Rust.

**License: dual MIT/Apache-2.0**, following the standard Rust ecosystem convention (the
same pattern used by `serde`, `clap`, and the Rust compiler itself):

- `LICENSE-APACHE` and `LICENSE-MIT` at the repo root, both already in place.
- A short statement in the README (already added) that contributions are dual-licensed
  under the same terms unless stated otherwise.
- Once a `Cargo.toml` exists, its `license` field should read `"MIT OR Apache-2.0"` (an
  [SPDX expression](https://spdx.github.io/spdx-spec/v3.0.1/annexes/spdx-license-expressions/)) —
  this is what crates.io and tooling like `cargo-deny` actually read;
  GitHub's own "License" sidebar badge may only reflect one of the two files, which is a
  cosmetic limitation of its detection tooling, not a problem with the licensing itself.

**IP policy:** to the extent vcrd ever needs to interact with proprietary or
restricted-license code (a patented algorithm, a dependency that isn't OSS-compatible),
that code must be isolated as an optional external module or plugin — never bundled into
or required by the open-source core. The trait-based extension architecture (§7) is what
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

## 6. Core Design Principles

These are the rules that keep the rest of the design coherent. Several of them exist
specifically because vcrd is meant to be consumed by more than one kind of frontend
(§7) — a rule that only works for the CLI isn't really a vcrd-core rule.

- **Read-only, no-network by default, with options for inbound and outbound requests.** Any
  operation that would write data or touch the network requires an explicit, per-operation
  opt-in.
  - **(a) Fully offline** — parse, validate, and offline verify (self-contained key
    material). This is the default: true especially for a first-time user who reads no
    documentation.
  - **(b) Opens a local listener, no outbound call** — e.g. standing up a local server to
    receive a wallet-interaction protocol message. Gated by its own opt-in,
    `--allow-inbound-network` (§8), separate from (c). Inbound exposure — something else
    connecting to a port vcrd opened — is a materially different risk shape than vcrd
    dialing out, so it doesn't belong lumped under the same flag. Note: making
    a local listener externally reachable is the user's own separate infrastructure
    decision (running `ngrok`, configuring a port-forward), not something vcrd does on
    their behalf.
  - **(c) Requires external network calls** — outbound resolution (`did:web`,
    a remotely-hosted revocation list — gated by `--allow-outbound-network`, §8).
- **Flags over prompts — every capability is reachable non-interactively.** No `vcrd`
  command ever blocks waiting on interactive input to do its job; every option is reachable
  via a flag, environment variable, or config value, in a single non-interactive
  invocation. This is what keeps vcrd usable unsupervised — by scripts, CI pipelines, and
  coding agents, none of which can answer a prompt. A frontend may layer an interactive
  mode on top for human convenience, but never as the only way to reach a feature.
- **`vcrd-core` takes its dependencies explicitly, rather than reaching for ambient
  state.** Concretely: a controllable clock is passed in (`now: DateTime`) rather than
  calling `SystemTime::now()`; randomness needed for proof generation is passed in via an
  `RngCore` rather than reaching for `OsRng` directly; DID resolution and JSON-LD
  `@context` document loading go through injectable resolver/loader traits, defaulting to
  a local vendored cache rather than a silent HTTP fetch. This is what makes "no network,
  fully offline, deterministic" something that can actually be verified rather than just
  hoped for, and it's what makes unit tests fast and non-flaky (§11) without mocking
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
- **Results represent graduated success, not a single pass/fail.** A multi-stage pipeline
  (parse → validate → verify) should let a caller see how far it got and why the next
  stage failed, rather than collapsing to one opaque error. If parsing succeeds but
  validation fails, the result carries both the successfully-parsed structure (or the
  useful parts of it) and the specific validation failure reason(s). This is what lets
  `vcrd inspect` (§8) give a useful answer even when a credential is broken,
  instead of an all-or-nothing failure.
- **Diagnosability: a failure pins down which pipeline tier failed, whose side it's on,
  and why.** This is one level more specific than graduated success above: it's not
  enough for a caller to see *that* a stage failed, they should get enough structure to
  act on the failure without hand-decoding tokens or cross-referencing spec text
  themselves. This matters most acutely for the mobile-wallet live-verifier feature (§9),
  where "whose side it's on" is what tells a caller whether they've hit a vcrd bug or a
  counterparty's non-conformance during a live protocol exchange. Related but distinct: a
  verify result also needs to enumerate what it did *not* evaluate (revocation, context
  resolution, holder-binding) with the same prominence as what passed (§12) — that's
  about disclosing scope, diagnosability is about localizing why a stage failed.
  Diagnosability is itself a testable property, not just an aspiration: tests assert on
  specific structured error variants/fields (§11), not merely that some error occurred.
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
  - *Ecosystem VC/OIDC4VP libraries (`ssi`, `openid4vp`, `isomdl`, and similar)*: settled
    exclusion, not a case-by-case call — never a direct production dependency of
    `vcrd-core` or `vcrd-cli`. These are strong, actively-maintained
    implementations (§3), but each is maintained by a company (SpruceID) optimizing its
    own product roadmap (mDL/gov-ID business) in a way that structurally can't guarantee
    to stay aligned with vcrd's own standalone/universal/unopinionated goals.
    Interoperability is demonstrated instead through differential testing against these
    and other independent implementations (§11) — comparing verdicts on identical input,
    not sharing a dependency graph. This exclusion applies to the shipped `[dependencies]`
    graph specifically; it does not preclude using these crates as Cargo
    `[dev-dependencies]` inside differential-testing tooling that never ships in the
    built binary (§11).
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
  already solve this well. One path deserves naming explicitly: RDF canonicalization
  (RDFC-1.0, required for JSON-LD Data Integrity, §10) has pathological "poison graph"
  inputs whose canonicalization cost is super-polynomial in graph structure, not linear in
  input bytes — the one place a small input can defeat the "core is fast by construction"
  principle above. The canonicalization step therefore enforces its own explicit
  iteration/permutation budget, failing closed (reporting a bounded-out condition, not
  silently returning a wrong or partial canonical form) rather than relying on the general
  size/depth/iteration limits above to catch it incidentally.

## 7. Architecture / Workspace Layout

A single Cargo workspace (resolver `"2"`, Rust 2024 edition), with `[workspace.package]`
inheritance for `version`, `edition`, `license`, `authors`, and `repository` so member
crates don't repeat this metadata.

- **`vcrd-core`** — the library. Owns the data model, the `CredentialFormat` and
  `ProofSuite` traits, and all parsing/validation/verification logic. No CLI dependencies,
  no `unsafe`, no ambient I/O (§6).
- **`vcrd-cli`** — the binary crate, depending on `vcrd-core`, owning `clap` and all
  presentation logic. Produces the installed `vcrd` binary (crate name and binary name can
  differ, the same way the `ripgrep` crate produces the `rg` binary, if that turns out to
  be convenient).
- **Deferred, future workspace members**: `vcrd-live-verify` (the mobile-wallet
  live-verifier feature, detailed in §9) and `vcrd-wasm`/`vcrd-browser` (a browser
  extension, most likely a thin shell around a WASM-compiled `vcrd-core`). Both are
  additional consumers of `vcrd-core` as a library, not modifications to it — reinforcing
  why core must stay origin-agnostic (§9). `vcrd-live-verify` implements the OpenID4VP-style
  protocol machinery once, with two role-specific entry points built on it — a verifier
  role and a wallet role (§9); exact CLI verb/subcommand naming for each is left as an
  implementation-time decision (§16).

  A tcpdump-style network-capture crate (sometimes called `vcrd-net`) is explicitly
  **out of scope** — not a deferred workspace member. A capture tool for
  identity credentials is an interception tool: wiretap/lawful-intercept statutes and
  privacy law apply, and the legitimate use case is thin, since credential exchanges
  already ride inside TLS, meaning passive capture would mostly show ciphertext anyway.
  The network-facing capability vcrd does offer is `vcrd-live-verify`: an
  actively-consented protocol exchange both sides participate in — in its primary form,
  one that vcrd itself drives on both ends (§9) — not passive traffic observation.

  The signing capability the wallet role needs (§9) is exposed from `vcrd-core`
  symmetrically to its existing verify capability — same key material, same crates,
  mirroring how most signing-algorithm crates already implement both directions — rather
  than duplicated inside `vcrd-live-verify`, keeping crypto logic centralized in core.

**Format and proof-suite implementations live as feature-gated modules inside
`vcrd-core`** (e.g. `jsonld`, `jwt-vc` Cargo features), not as separate per-format crates.
This was a deliberate choice to avoid premature architecture: splitting a module out into
its own crate later, if an external contributor wants to ship one independently, doesn't
require breaking the trait contract that already exists. The trait boundary is what
provides extensibility; crate-level separation is an implementation detail that can follow
demand rather than precede it.

Note for `ProofSuite` specifically: because AnonCreds/BBS+ (with optional Bulletproofs
range proofs, §10) involve proofs that reveal only a subset of claims rather than a simple
"verify a signature over these exact bytes" operation, the trait should be designed with
room for partial/selective-disclosure proofs from the start, even though those formats
aren't implemented first. Retrofitting that shape after the trait is load-bearing API
would be far more disruptive than designing for it now.

**Versioning**: all crates currently share a single workspace version via
`version.workspace = true`. This is intentional for now (single maintainer, no reason for
crates to diverge), but the mechanism already supports splitting — moving a crate to an
independent version later is a one-line change (drop `.workspace = true`, set a literal
version), not a restructuring. This intent will be documented explicitly (e.g. in
`CONTRIBUTING.md`) so a future split doesn't look accidental.

**Workspace-level lints** (`[workspace.lints.clippy]`): deny `unwrap_used`, `expect_used`,
and `indexing_slicing` outside test code, enforcing the no-panic-on-untrusted-input rule
from §6. This also sets up future fuzzing (§11) to be meaningful — a fuzzer finding "this
panics" is only useful if panics were supposed to be impossible.

## 8. CLI Design

`vcrd-cli` uses a modern, verb-first subcommand structure, in the style of tools like `cosign`, `age`,
`gh`, and `cargo` (contrasted with older single-command, flag-heavy CLI conventions):

- `vcrd inspect <file>` — combines the parse and validate tiers (§4) into a single verb;
  human-readable by default. There is deliberately no separate `validate` subcommand:
  validating something that failed to parse isn't a meaningful operation on its own, so
  `inspect` always runs both and reports on whichever stage it actually reached. Failure
  behavior, subject to the verbosity level below:
  - If parsing itself fails, `inspect` reports *why* — what was expected, what was found,
    not just "parse failed at line X character Y."
  - If parsing succeeds but validation fails, `inspect` still surfaces whatever useful
    information the parse extracted, and separately explains why validation failed —
    never collapsing a partially-successful result into a bare failure.
  - `validate` remains a `vcrd-core` capability (§4); it's just not exposed as its
    own top-level verb today. Nothing rules out adding a flag or subcommand for
    validate-only output later if a concrete use case for it shows up.
- `vcrd verify <file>` — offline-only unless `--allow-outbound-network` is allowed (§6); this flag is global, not per-subcommand, so it can't be missed.
  `--allow-inbound-network` is the separate opt-in for operations that open a local
  listener without dialing out (§6) — distinct because inbound exposure is a different risk
  shape than outbound resolution, not a subset of it.
- `vcrd formats` / `vcrd suites` — list supported credential formats and proof suites
  (discoverable capability probing, useful for both humans and agents).

**Defaults matter.** Running `vcrd <file>` with no subcommand, or piping input via
`cat file | vcrd`, defaults to `inspect` at the default verbosity level and format —
a novice gets a useful answer without reading documentation first.

**Cross-cutting flags**: `--verbose`/`--verbosity` (diagnostic detail level, down to a
`0` setting that suppresses all output and relies solely on the exit code — useful for
scripting that only cares whether something passed) and `--format json|text|plain`
(output shape). stdout is reserved for the actual result (so output stays pipeable);
stderr carries diagnostics and progress. Distinct exit codes distinguish parse failure,
validation failure, and verification failure, so a calling script can branch on which
kind of failure occurred rather than just "something went wrong."

**Redaction-aware output by default; `--unsafe` opts out.** vcrd's own output is a leak
surface: printing full claim sets — including PII and, for SD-JWT, disclosed values —
into terminals, CI logs, and agent transcripts is exactly the exposure a careful user
already avoids when handling live credentials by hand. Every output format (`text`,
`json`, `plain`) redacts claim *values* by default, while still showing claim *names*,
document structure, and all non-claim metadata (issuer, type, dates, algorithm/proof-suite
names) in full — none of that is sensitive, and all of it is needed for diagnosis.
When it's useful and practical, a redacted
value is replaced by a deterministic hash (truncated to a short, human-scannable form)
rather than elided to nothing, so a caller can tell whether the same field matches or
differs across two credentials/transactions without ever seeing the plaintext — the
debugging need this default serves, not just a privacy stance. An unsalted hash doesn't
meaningfully protect a low-entropy field (a boolean, a small enum, a birth year), so
these kinds of fields should be masked instead of hashed.
`--unsafe` (global, same family as the network opt-in flags,
§6) disables redaction and prints full cleartext claim values; using it triggers both a
human-visible stderr warning banner and a structured marker in the result itself (e.g. a
top-level `unsafe_cleartext` field in JSON output), so a script or agent consuming
stdout — not just a human reading a terminal — can detect that the output is unredacted
and handle it accordingly (e.g. refuse to persist it into a shared log store).
`--verbose` is orthogonal to this: it raises diagnostic detail (which pipeline tier,
timing, structural info), never claim-value cleartext — only `--unsafe` crosses that
line.

**Tabular rendering** for the `text` format uses the [`tabled`](https://crates.io/crates/tabled)
crate, chosen over the more-downloaded `comfy-table` alternative: `tabled`'s
`#[derive(Tabled)]` approach generates a table directly from a struct, which scales better
across vcrd's eventual breadth of format-specific structs (§3, §10) — many credential
formats and proof suites, each with its own shape to render — than hand-building rows
per format the way `comfy-table` requires. This choice is scoped to `text` rendering only;
JSON output stays `serde_json`, independent of whatever renders `text`.

**Configuration file** lets any of the above become a permanent default instead of a
per-invocation flag — a human who always wants `--format json`, or who always works
against `did:web`-resolving issuers and is tired of retyping `--allow-outbound-network`, sets it
once. A single user-global TOML file (standard per-OS config directory, e.g. via the
`directories` crate convention — no project-local/repo-local layer for now) holds
defaults for `--format`, `--allow-outbound-network`, and `--allow-inbound-network`. Precedence is
flag > environment variable > config file > built-in default, and parsing this file is a
`vcrd-cli` concern, not a `vcrd-core` one — consistent with core doing no ambient I/O or
environment-variable reads of its own (§6, §11).

**`clap`** (derive macros) handles argument parsing, `--help` generation, shell completion
generation, and man-page generation (`clap_mangen`) — all close to free once the argument
structs are defined, and all automatically stay in sync with actual CLI behavior rather
than drifting like hand-maintained docs would.

**Accessibility conventions**: pass/fail is never signaled by color alone (always paired
with text — "PASS"/"FAIL", not just a colored symbol), and the `NO_COLOR` environment
variable convention is honored.

**Progress reporting** is a frontend concern, not a core one, per §6 — and ideally
`vcrd-core` never needs it at all, since its operations are meant to stay fast by
construction. Where a *frontend* offers a long-running feature (the running
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
while a full dependency/SBOM-style manifest (useful for supply-chain verification, §12) is
likely too much noise for that use case and probably belongs behind a separate, explicit
command instead of folded into general `--verbose`. Both of these are open items — see
§16.

## 9. Input/Output Modalities

**Input**: files and stdin/pipes are the initial supported modalities. A browser
extension and the mobile-wallet live-verifier feature below are explicitly anticipated
but deferred to separate crates (§7). The live-verifier feature specifically adds a
network input modality — receiving a presentation over a local listener, per the
network taxonomy in §6 — but that's a `vcrd-cli`/future-crate concern, not a change to
this contract:
`vcrd-core`'s functions take bytes in and don't know or care where those bytes came from —
that's what lets every current and future frontend share the same core logic.

**Mobile-wallet live-verifier feature.** Rather than only reading a presentation someone
already has in hand, this feature has vcrd actively request one from a wallet over a live
protocol exchange.

*Primary path, fully CLI-driven.* `vcrd` plays both roles: a verifier (opens a local
listener, tier (b) §6, gated by `--allow-inbound-network`) and a scriptable wallet-side
counterpart (connects to that listener, tier (c) outbound from the wallet role, gated by
`--allow-outbound-network`) — both invoked from the command line, no external device
needed. Worth stating explicitly: even though nothing leaves the local machine, both
opt-in flags still apply, one per role — §6 doesn't carve out a "trusted because it's
loopback" exception, and this feature is no different. The wallet-side counterpart
presents one of vcrd's own curated example credentials (§11), signing a fresh
holder-binding proof over the verifier's actual request nonce on every run rather than
replaying a canned response — a spec-compliant round trip, and a
self-contained way to validate vcrd's own protocol implementation with no external
dependency at all.

*Secondary path, built after the primary one works.* Rendering the verifier's request as
a QR code and accepting a response from a real external mobile wallet — the
interop-facing form of the same feature, worth building once the protocol mechanics are
proven against vcrd's own wallet-side counterpart first, not before.

*Protocol.* Follows the OpenID4VP family of specs, the dominant real-world mechanism for
this exchange. Per §6's dependency policy, vcrd implements this against the published
spec itself rather than depending on an existing OpenID4VP library; independent
implementations are used only as differential-testing oracles (§3, §11).

*Format scope.* A CA-issued mobile driver's license (mDL) is the feature's motivating
real-world example, but the feature ships independent of mdoc: it works against
whichever credential formats vcrd already supports (§10). Actual mDL presentations wait
on mdoc format support landing, unchanged by this feature's scoping.

*Trust boundary.* Cryptographically verifying the wallet's holder-binding proof and the
issuer's signature (tiers 1–3, §4) is not the same as knowing the issuer is a real,
accredited authority — for a government-grade credential like an mDL, that's gated by an
ecosystem accreditation/trust-list scheme, not by anything a valid signature alone
establishes. Per §1/§4's tier-4 trust-evaluation boundary, the live-verifier feature
performs verification, not trust evaluation. Consistent
with §6's dependency-injection principle, vcrd doesn't ship or maintain a trust list — a
caller who wants issuer-accreditation checking supplies their own trust anchor as
explicit input, the same way DID resolution and `@context` loading are already
injectable rather than hardcoded.

**Output**: structured JSON, well-formatted (tabular where appropriate, via `tabled`, §8)
human-readable text, and unformatted/plain text are the three initial formats. JSON deliberately doubles as the
agent-facing format — there is no separate "agent mode" output, and no natural-language
summarization baked into vcrd itself. Redaction-aware output (§8) applies uniformly
across all three formats, JSON included: since JSON is the agent/CI-log-facing default,
exempting it from redaction would leave exactly the leak surface that default exists to
close. This is intentional: the future risk/trust-advice
tool (§1) is meant to be built on top of vcrd, and vcrd staying unopinionated about that
higher-level use case means it shouldn't bake in assumptions about what such a system
needs. Plain structured JSON is the more general, more reusable choice.

Coding/code-aware agents being the primary design lens (§1) doesn't mean the other formats
are deprioritized: `tabular`/`text` are fully-supported, first-class outputs for human use. The no-flag default stays `text` (§8) — a human at a terminal
still gets a readable answer without needing to know vcrd exists to serve agents too.
Because a human's preferred default may reasonably differ from vcrd's own default without
that person wanting to type `--format text` on every invocation, that default is
overridable in one place, permanently, via the configuration file described in §8, rather
than only per-invocation.

## 10. Initial Format & Verification Scope

Initial format support: **one JWT-based VC format**, plus **JSON-LD with Data Integrity
proofs** — the JWT-based format leads because it starts on the JOSE verification path,
which is materially less initial implementation surface than RDF canonicalization
(RDFC-1.0, required for JSON-LD Data Integrity) — a substantial, subtle machine in its
own right. This is a sequencing choice, not a scope one: JSON-LD + Data Integrity is
still committed as the second format in this same initial phase, not deferred
indefinitely. (The exact JWT-based format to implement first is an implementation-time
decision, not pinned here — the intent is to start with whichever shape is easiest to
implement, then follow quickly with SD-JWT VC's fuller selective-disclosure
functionality, below.)

**JOSE algorithm coverage is a first-class requirement of the JWT-based path, not an
implementation detail left to whichever crate is picked.** Algorithm support should be as
broad as practical across the standard JOSE signature algorithm set, not just the common
ES256/RS256 subset, and an algorithm outside what's supported must fail **by name** —
naming the unsupported algorithm and what is supported — rather than surfacing as an
opaque parse error (§6's diagnosability principle applied concretely here). This is
directly evidenced, not aspirational: EUDI's real-world default signing algorithm
(ES512/P-521) turned out to be unsupported by two of three Rust JOSE crates evaluated,
blocking an otherwise-clean interop round trip outright with no indication of why.

**Presentation support (§2) rides along with each credential format, rather than being a
separate, indefinitely-deferred feature** — per format, the plan is to land credential
(VC) support first and presentation (VP) support for that same format as a follow-on,
in a separate PR rather than requiring both together. This is a provisional commitment:
if presentation support for a given format turns out to be disproportionately complex
relative to its credential support, that's reason to revisit scope for that format
specifically, not a reason to abandon the general principle.

**Presentation verification needs protocol inputs, not just cryptography.** A VP's
holder-binding proof is only meaningful when checked against a verifier-supplied
challenge/nonce and domain/audience — without that check, a replayed presentation
verifies perfectly well cryptographically. `verify` on a VP therefore takes optional
expected-challenge/expected-domain parameters in v1 of the API, not retrofitted later:
changing the result schema after it's load-bearing would be disruptive. When those
parameters are absent, the result reports "holder-proof cryptographically valid,
replay-binding not evaluated" rather than a bare pass, per §6's diagnosability and
non-checks-enumeration principles.

Near-term roadmap: [**SD-JWT VC**](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/),
given its real-world adoption in wallet ecosystems.

Named future direction, deliberately not built first: **AnonCreds and BBS+ signatures,
optionally combined with Bulletproofs for zero-knowledge range proofs.** This is a
different verification paradigm from a simple signature check (§2, §7) and is the reason
`ProofSuite` needs to anticipate partial/selective-disclosure proofs architecturally, even
before it's implemented. Relevant open-source prior art in Rust: Hyperledger's
`anoncreds-rs` (the official successor to the older `libindy`/`ursa` stack) and Dock's
`proof-system`/crypto crates, which already implement BBS+ with bulletproofs-style range
proofs.

Noted but deprioritized for the initial implementation: **mdoc/mDL** (ISO 18013-5) — it
uses a different serialization and proof paradigm entirely (CBOR/COSE, plus
device-engagement and session-transcript mechanics) from the two JSON-based formats
prioritized above, so it isn't an incremental step from either and is deferred as a
scope decision rather than a blocked one. This deferral also bounds the mobile-wallet
live-verifier feature's (§9) initial scope: a CA mDL is that feature's motivating
real-world example, but actual mDL presentations aren't handled until mdoc format
support lands here.

**DID resolution** starts with offline-resolvable methods (`did:key`, embedded JWKs);
network-dependent resolution (`did:web` and similar) is available only with the
`--allow-outbound-network` opt-in described in §8.

**Explicitly out of scope for this phase**: issuing and editing credentials (a later
phase built on the same core), and the risk-based trust-advice layer described in §1
(a separate program entirely).

## 11. Testing Strategy

- **Unit tests** live alongside the code they test in `vcrd-core`, and must run fully
  offline with no external-state dependencies — no network, no reliance on system clock,
  no ambient filesystem/environment coupling (§6 makes this possible by construction
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
  deliberately deferred to a two-branch implementation spike (§16) rather than decided in
  the abstract.
- **Curated example library**, separate from the vendored fixtures above: vcrd maintains
  its own small set of hand-authored example credentials — one canonical, self-signed,
  offline-verifiable credential per supported proof format, expanding as format support
  grows (§10). Unlike the vendored conformance fixtures, these are vcrd's own original
  content, so no redistribution-rights tracking is needed; they're covered by the
  project's own license like any other repo file. The library serves double duty: it
  supplies the known-good positive fixtures the test suite exercises, and it's what
  README/quickstart documentation points to directly for a first successful `vcrd verify`
  run, rather than embedding illustrative credential JSON inline in prose — keeping docs
  and tests pointed at the same local examples. Signing these examples
  doesn't reopen §10's issuing-is-out-of-scope stance: they're static files, committed to
  the repo rather than regenerated at test time, produced by a dev/test-only helper
  (`#[cfg(test)]`-gated or under `dev-dependencies`, never shipped in the `vcrd-core`
  library artifact or the `vcrd` binary) that signs using the same signing-algorithm
  crates vcrd-core already depends on for verification — most such crates implement both
  `Sign` and `Verify` from the same key material, so no new dependency is needed. This is
  internal repo tooling, the same category as the `criterion` benchmarks or the `fuzz/`
  seed corpus below, not the shipped issuance feature §10 defers, and not a use of the
  ecosystem libraries §6/§11 already decided against depending on directly; it needs no
  workspace member of its own, unlike `fuzz/`, and lives alongside vcrd-core's existing
  test suite instead. This helper reuses the signing capability `vcrd-core` exposes for
  the mobile-wallet live-verifier feature's wallet-side counterpart (§9, §7) rather than
  implementing a separate scheme; the helper itself stays dev-only and never-shipped, per
  the description above.
- **Differential testing** validates vcrd's own verification logic against independent
  implementations of the same specs, rather than only against hand-written fixtures: feed
  an identical credential/presentation to vcrd and to another implementation, and compare
  verdicts. A disagreement is almost always a real bug in one side or the other, and the
  disagreeing case is itself the fixture that pinpoints it — no one has to hand-derive the
  "correct" answer the way an example-based test requires. This is what makes §6's
  dependency-policy exclusion safe rather than isolating: interoperability is demonstrated
  this way instead of by coupling to those libraries in `vcrd-core`'s shipped dependency
  graph. Tools hands-on-validated as viable oracles: openid4vp's reference
  wallet and verifier, a self-hosted walt.id identity instance (JWT/SD-JWT/mdoc via
  OpenID4VCI/OpenID4VP), and the EUDI verifier-endpoint reference implementation (SD-JWT
  VC). Two further candidates are scoped out for now rather than evaluated (§3): the
  official W3C VC Data Model/VC-JOSE-COSE and OpenID Foundation conformance test suites,
  and TBD's `ssi-sdk`/web5 stack. Exact harness mechanics (a dedicated workspace crate, ad
  hoc scripts, a separate CI job) are left as an open item (§16).
- **Negative and adversarial fixtures are a required category, not an afterthought.**
  Given vcrd's whole purpose is trust-relevant checking, "known-good credential verifies
  successfully" fixtures are only part of the test matrix. Required
  coverage includes: expired, not-yet-valid, revoked, tampered-signature, wrong-issuer,
  abnormal size or depth, and malformed-`@context` cases, plus — specifically —
  **algorithm-confusion attacks** (e.g. tricking a verifier expecting RS256 into accepting
  an HMAC-signed token using the
  public key as the secret, or accepting `alg: none`). This class of bug has repeatedly
  and concretely affected JWT/JOSE implementations and needs to be a named test
  category from the start, since vcrd implements verification itself rather than wrapping
  an already-hardened library. Alongside it, **unsupported-algorithm rejection** (§10) is
  its own required fixture category: a credential signed with an algorithm outside vcrd's
  supported set must be asserted against the specific by-name error (naming the algorithm
  and what is supported), not just a generic verification failure — the same fuzz corpus,
  property tests, and differential-testing oracles below apply to it, no separate testing
  machinery is needed.
- **Property-based tests** (`proptest`) are included from the start alongside unit tests
  — round-trip (`parse(serialize(x)) == x`) and invariant (canonicalization idempotency)
  checks catch a different class of bug than example-based tests and are cheap to add as
  core modules are built.
- **Fuzzing** (`cargo-fuzz`) is deferred to implementation time, but the workspace is
  prepared for it now: the no-panic-on-untrusted-input lint policy (§6, §7) is what makes
  a fuzz target meaningful, and the same vendored conformance fixtures will double as seed
  corpus. The `fuzz/` directory, when added, is excluded from the main workspace since it
  needs a nightly toolchain.
- **Externalized state for determinism**, beyond just the clock (§6): randomness used in
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
  SHA — not a `curl | bash` uploader script, which was the actual vector in a 2021
  supply-chain compromise that used Codecov's bash uploader to exfiltrate CI secrets from
  downstream projects.

## 12. Security Posture

**Threat model (lightweight, to be promoted to `docs/threat-model.md` once implementation
is further along):**

- **Adversary**: a malicious or careless credential issuer or holder, attempting either
  to get vcrd to report a false "valid"/"verified" result, or to crash or exploit vcrd via
  a malformed or adversarially-crafted credential file. vcrd's core purpose — checking
  credentials from parties that aren't trusted — makes this a realistic threat even for a
  purely local, offline CLI invocation, not a hypothetical one.
- **In scope**:
  - Parsing, validation, and verification correctness (including the algorithm-confusion
    and malformed-input categories named in §11).
  - **JSON-LD context substitution.** In JSON-LD credentials, `@context` controls the
    *meaning* of every term — a signature can remain valid over canonicalized RDF while a
    manipulated or attacker-hosted context silently changes what the claims mean.
    Verification against an unpinned or unresolvable context is a distinct,
    loudly-reported condition, never a silent fetch-and-proceed, even under
    `--allow-outbound-network` — surfaced with the same prominence as an
    algorithm-confusion failure, not folded into a generic parse/validate error. The
    vendored context cache and injectable loader trait (§6) are the mechanism; this is
    the policy governing what happens when a context falls outside that cache.
  - Resource exhaustion via oversized or pathologically-structured input, including the
    RDF-canonicalization iteration/permutation budget (§6's structural limits).
  - Memory safety (addressed largely for free by Rust plus the
    `#![forbid(unsafe_code)]` policy).
- **Result-contract non-checks.** Per §6's diagnosability principle, a `verify` result
  names what it did *not* evaluate — revocation/status-checking, context resolution
  beyond the pinned cache, and holder-binding on presentations (§10) — with the same
  prominence as what passed. This is what prevents "verified: true" from being misread as
  "trustworthy" (§1's non-goal), the false-assurance failure mode this threat model exists
  to guard against.
- **Explicitly deferred, named so the gap is deliberate rather than accidental**: the
  broader network-facing threat model (out of scope while network access stays opt-in
  and off by default) — except for the minimum hardening bar below, which can't wait,
  since tier-(c) network calls (`did:web`, remote revocation lists, §6) are already in
  initial scope; most secret-key handling and storage. Verification primarily operates
  on public key material, and general issuance (§10, which would need durable private
  signing keys) is implemented in a later phase. The mobile-wallet live-verifier
  feature's wallet-side counterpart (§9) does need a narrowly-scoped runtime signing
  capability: a holder-binding proof over an existing credential's presentation, not a
  new credential — distinct from general issuance. Scoped minimally: that counterpart
  generates an ephemeral holder keypair fresh per invocation rather than persisting one,
  so no secret-storage-at-rest subsystem is needed. Persistent keys, at-rest encryption,
  and HSM/KMS integration remain deferred until general issuance (§10) enters scope.

**Network minimum hardening bar**, scoped to tier-(c) external network calls (§6) —
`did:web` resolution and remotely-hosted revocation/status lists — since these are
already in initial scope even though the broader network threat model is deferred above:

- HTTPS-only with certificate validation; no flag disables this. Testability doesn't
  require weakening it: the client's trust anchor is itself injectable, mirroring §6's
  DID-resolver/context-loader injection pattern — defaulting to the system trust store
  in production, letting tests supply an ephemeral, in-process test CA (e.g. via the
  `rcgen` crate) rather than trusting a modified system/browser trust store or disabling
  validation.
- Response size caps and a bounded redirect count, reusing §6's structural-limits
  principle rather than inventing a separate mechanism.
- An SSRF stance for `did:web` resolution: the *resolved* socket address, not the
  hostname string, is checked before connecting, and a resolution landing on a
  link-local, private, or loopback range is refused by default. This matters
  the moment vcrd runs inside CI or server-side tooling, where an attacker-supplied
  `did:web` value could otherwise be pointed at an internal host or a cloud metadata
  endpoint.
- **Loopback carve-out, scoped narrowly.** The mobile-wallet live-verifier's primary path
  (§9, §10) is a fully local round trip between vcrd's own two roles on one machine — no
  network hop exists for a MITM to sit on, so HTTPS-only doesn't protect against anything
  real there. That path is exempt from this bar (plain HTTP over loopback is fine,
  precedented by RFC 8252's native-app loopback-redirect pattern), but the exemption is
  keyed off the same resolved-socket-address check as the SSRF stance above — an actual
  loopback address, verified at connection time — not a hostname that merely claims to be
  `localhost`. This keeps the carve-out from doubling as a bypass for the SSRF stance it
  sits next to.

**Supply chain**: `cargo-audit` and `cargo-deny` run in CI, checking dependencies against
the RustSec advisory database and enforcing license compliance. `Cargo.lock` is committed
and tagged at every release (workspace crates produce an installed binary, so pinning
exact versions is standard practice here even though a library-only crate typically
wouldn't commit its lockfile). Longer-term, not needed immediately: publishing a
Software Bill of Materials per release (`cargo cyclonedx` or similar), baking build/
dependency metadata into the binary itself so it's self-reporting even without source
access (tying into the diagnostic API discussed in §8), and signed/reproducible releases.

**Crypto dependency selection criterion**: prefer crates that explicitly document
constant-time/side-channel handling (RustCrypto and `dalek-cryptography` crates generally
do, and the `subtle` crate exists specifically to give this ecosystem constant-time
primitives to build on). Any crate selected despite not documenting this gets named
individually as a watch/upgrade/replace candidate at the point it's chosen — this is a
selection-time policy, not a task to track before any crate has actually been picked.

**`SECURITY.md`**, present from the start of the project: a reporting channel (GitHub's
private security advisory feature, avoiding separate email infrastructure), a
best-effort/pre-1.0 response expectation rather than an SLA that can't be backed, a
"supported: main branch only" statement while pre-1.0, and a pointer to the threat model
above. It also carries a plain-language reliance/liability stance: people will make real
decisions based on vcrd's output, and the MIT/Apache warranty disclaimers cover only the
legal floor, not the practical one — so `SECURITY.md` states directly that vcrd is
pre-1.0 and not to be relied on for production trust decisions. This reinforces §1's
existing non-goal (vcrd reports facts, trust evaluation is a separate future layer)
rather than duplicating it — that non-goal is about scope, this is about maturity.

**GitHub Actions / CI hardening**, adopted immediately even while the project is
solo-maintained, since retrofitting these habits after bad patterns are established (or
after an incident) is far more painful than starting clean:

- Untrusted PR code never runs with secrets or write access. The dangerous trigger is
  `pull_request_target`, which runs with the base repo's token/secrets but can be pointed
  at the PR's own (attacker-controlled) code — this exact pattern has caused
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

## 13. Release, Versioning & Documentation Tooling

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
  and checksums as part of the same pipeline (tying back to §12's supply-chain goals).
- **Documentation**: CLI reference documentation and man pages are generated directly from
  the `clap` argument definitions (`clap_mangen` and similar), so they can't drift out of
  sync with actual CLI behavior the way hand-maintained docs would. README + doc comments
  + this generated CLI reference are sufficient for now; a higher-level conceptual guide
  (mdBook-style) is deferred until there's enough surface area to justify the
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

## 14. Contribution & Community Structure

Kept deliberately light while the project is solo-maintained — the right frame is "rules
the maintainer already follows, written down now so they apply to any future
contributor," not a heavyweight process built in advance of needing one.

**Community presence is the primary contributor-acquisition strategy — the repo-hygiene
items below are necessary but insufficient on their own.** A polished `CONTRIBUTING.md`
and issue templates only help a contributor who has already found the project; they
don't manufacture discovery. The higher-leverage path is showing up where the identity
ecosystem already congregates: participating in the W3C Verifiable Credentials Working
Group / Credentials Community Group, registering vcrd against the official W3C VC test
suites (also a candidate differential-testing oracle, §3, §11), taking part in
interop events and plugfests, and filing issues against the specs themselves when
implementation surfaces a real ambiguity. That's where vcrd's actual target audience —
other implementers, tool maintainers, the standards community — looks for tools worth
trying, not the repo's own issue tracker.

- **`CONTRIBUTING.md`** covers: local build/test commands; the PR workflow (short-lived
  branch off `main`); a pointer to the trait-based extension points in `vcrd-core`
  (`CredentialFormat`, `ProofSuite`) as the main on-ramp for a contribution, since adding
  a new format/suite is the most likely thing an outside contributor wants to do; an
  explicit, welcoming note that platform support (Windows, etc.) is open territory rather
  than an apologized-for gap; and a pointer to `SECURITY.md` for vulnerability reports
  rather than the public issue tracker.
- **Issue and PR templates**: a bug report template nudges reporters to include vcrd's
  diagnostic/version output (§8), and explicitly warns against pasting a real, live
  credential into a public GitHub issue — VCs can carry real personal data, and encouraging
  synthetic/test fixtures instead is a deliberate norm for a tool whose whole purpose is
  handling this kind of data carefully. A PR template checklist covers: tests pass
  offline, `clippy`/`fmt` clean, and flags changes touching `.github/workflows/` or adding
  a new dependency for extra scrutiny (§12).
- **`CODE_OF_CONDUCT.md`** adopts the Contributor Covenant as-is, rather than a
  custom-authored document — it's the de facto standard across the Rust ecosystem and
  contributors already know it. Its reporting section needs two things settled before the
  project actively invites outside contributors: a dedicated project contact
  alias (rather than the maintainer's everyday personal email, for portability and light
  privacy separation) and an identified secondary/backup contact who isn't the primary
  maintainer, specifically so a report *about* the maintainer has a safe channel — the
  template alone doesn't solve this for a solo project.
- **Commit conventions**: free-form while solo, by deliberate choice. The switch to
  Conventional Commits (`feat:`/`fix:`/`chore:`/etc., enabling automated `CHANGELOG.md`
  generation via a tool like `git-cliff`) is deferred, but gated on the same milestone as
  the community files above: **before the project starts being discussed with other
  people.** Retrofitting a commit convention partway through leaves a gap in generated
  history, so this is a "do it right before it matters" decision rather than "do it
  whenever."

## 15. Glossary

- **CBOR** — Concise Binary Object Representation, the binary serialization mdoc/mDL
  credentials use in place of JSON.
- **COSE** — CBOR Object Signing and Encryption, the CBOR-based analog to JOSE's
  signing/encryption mechanics.
- **DID** — Decentralized Identifier.
- **DIDComm** — DID Communication, a secure agent-to-agent messaging protocol built on
  DIDs.
- **EIP-712** — Ethereum Improvement Proposal 712, a typed structured-data
  message-signing standard.
- **EUDI** — the EU Digital Identity Wallet program, producer of the `verifier-endpoint`
  reference implementation discussed in §3.
- **FFI** — Foreign Function Interface, a dependency that crosses a non-Rust language
  boundary.
- **HSM** — Hardware Security Module.
- **JOSE** — JSON Object Signing and Encryption, the IETF framework covering JWS/JWK/JWT.
- **JWK** — JSON Web Key.
- **JWS** — JSON Web Signature.
- **JWT** — JSON Web Token.
- **KMS** — Key Management Service.
- **mDL** — mobile driver's license.
- **mdoc** — the ISO 18013-5 "mobile document" CBOR-encoded credential format that mDLs
  are an instance of.
- **MITM** — Man-in-the-Middle (attack).
- **MSRV** — Minimum Supported Rust Version.
- **OIDC** — OpenID Connect.
- **OpenID4VCI** — OpenID for Verifiable Credential Issuance.
- **OpenID4VP** — OpenID for Verifiable Presentations.
- **PII** — Personally Identifiable Information.
- **RDF** — Resource Description Framework, the data model JSON-LD credentials are
  canonicalized as.
- **RDFC-1.0** — RDF Dataset Canonicalization 1.0, the W3C canonicalization spec used by
  JSON-LD Data Integrity proofs.
- **SBOM** — Software Bill of Materials.
- **SD-JWT / SD-JWT VC** — Selective Disclosure JWT / Selective Disclosure JWT
  Verifiable Credential.
- **SPDX** — Software Package Data Exchange, the license-identifier format used in
  `Cargo.toml`'s `license` field.
- **SSRF** — Server-Side Request Forgery.
- **TTY** — teletypewriter, i.e. an interactive terminal.
- **URDNA2015** — Universal RDF Dataset Normalization Algorithm 2015, RDFC-1.0's
  predecessor.
- **VC** — Verifiable Credential.
- **VC-API** — the W3C Credentials Community Group's HTTP API specification for VC
  issuance/verification services.
- **VP** — Verifiable Presentation.
- **WASM** — WebAssembly.

## 16. Open / Deferred Items

These are deliberately deferred rather than decided now. This document is the durable,
canonical record of these open items.

1. **VC-API vector-consumption spike**: build two throwaway branches when implementing
   JSON-LD/Data Integrity — (a) extract W3C VC-API-shaped test vectors and adapt them into
   direct calls against `vcrd-core`, versus (b) a minimal local VC-API HTTP shim so the
   official test harness runs unmodified. Compare the actual working code and the delta
   from `main` on each, then merge the winner and discard the other.
2. **Set up `cargo-fuzz` targets** for `vcrd-core`'s untrusted-input parsers, seeded from
   the same vendored conformance fixtures used in testing (§11).
3. **Fable-based review of this document**, with particular attention to security risks —
   threat model completeness, verification-bypass classes, resource-exhaustion surface,
   crypto dependency choices, and any other design-level security gap, before
   implementation starts in earnest.
4. **Research non-flaky test patterns** for `vcrd --version --verbose`-style output, once
   that feature is actually built — naive tests would be coupled to the exact build
   environment/commit/timestamp.
5. **Switch to Conventional Commits and add `CHANGELOG.md`**, gated on "before talking to
   other people about the project" (§14).
6. **Wire up `cargo-semver-checks`** in CI before the 1.0 release (§13).
7. **Add `CONTRIBUTING.md`, issue/PR templates, and `CODE_OF_CONDUCT.md`** to the repo,
   same gating milestone as item 5 (§14).
8. **Enable GitHub's "require approval for first-time contributor workflows" setting** —
   an early-setup item, not gated on going public, since it costs nothing while solo
   (§12).
9. **Add a `CODEOWNERS` entry for `.github/workflows/*`** — same early-setup timing as
   item 8 (§12).
10. **Design `vcrd-core`'s diagnostic/build-info API**, with `vcrd-cli`'s
    `--version --verbose` as one consumer of it rather than a CLI-only feature, and
    resolve the still-open scope question between ordinary bug-report-oriented output and
    a full dependency/SBOM-style manifest (§8).
11. **Identify a secondary Code of Conduct contact** — someone other than the primary
    maintainer — before openly and actively inviting outside contributors (§14).
12. **Set up `cargo-llvm-cov` coverage tracking** with the ratchet (not hard-gate) policy
    described in §11, and document that policy in `CONTRIBUTING.md`.
13. **Scope the mobile-wallet live-verifier feature's initial OpenID4VP protocol
    coverage** (which request/response variants, response-mode/encryption handling,
    credential-query mechanism) and its CLI verb/subcommand naming for the verifier and
    wallet roles, once implementation starts (§9, §7).
14. **Design the live-verifier feature's trust-anchor input mechanism** — how a caller
    supplies their own root-of-trust/accreditation material for issuer trust checks
    (§9) — a flag-vs-config-file question deferred to implementation time, consistent
    with §8's existing config-file precedent.
15. **Design the secondary QR-code + external-wallet path** for the live-verifier
    feature (§9), once the primary self-contained round trip (vcrd playing both roles)
    is implemented and working.
16. **Choose the JOSE dependency** against §10's algorithm-coverage requirement. Data
    point on record: `josekit` was confirmed to have full
    ECDSA-family algorithm coverage (including ES512/P-521) on paper, though its maturity
    wasn't vetted; `jsonwebtoken` and `ssi-jwk` both stop at ES384. Not a decision now —
    the actual selection happens when the JWT-based format lands.

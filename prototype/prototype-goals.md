# Prototype Goals

Based on [REQUIREMENTS.md](REQUIREMENTS.md), here are some questions that can be answered by building a prototype.

## Questions only the prototype can settle

**1. What shape is the graduated result, actually?**
This is the highest-stakes one. §6 asks for three things that fight each other in Rust's type system: graduated success (parse OK / validate failed / verify not reached), tier-localized diagnosability ("whose side is it on"), and a non-checks enumeration carried with the same prominence as passes ([REQUIREMENTS.md:859](REQUIREMENTS.md:859)). `Result<T, E>` is binary and none of that fits it cleanly. The prototype forces the decision: `Result<Report, FatalError>` where `Report` itself carries per-tier outcomes? One accumulating struct, or a type per tier? Is the payload generic over format, or an enum with a format-specific variant — i.e. is adding SD-JWT later additive or a breaking change to every consumer's match?

**2. Is `vcrd-core`'s struct layout the public JSON schema?**
The tempting move is `#[derive(Serialize)]` on core's result types and let `--format json` fall out. If you do that, core's internal field names *are* the agent-facing wire contract, and every refactor is a breaking output change — which sits badly with §6's "core stays UI-agnostic." The alternative is a CLI-side view model and a deliberate schema. You can only feel which one you want by writing both ends once. Related: what does `--format json` emit when *parsing* fails? An agent needs a JSON envelope for failures too, not a bare stderr string and empty stdout.

**3. Where does redaction live, and can it be made structurally hard to bypass?**
§8 makes redaction the default across all three formats, with truncated deterministic hashes for high-entropy values and masking for low-entropy ones ([REQUIREMENTS.md:479](REQUIREMENTS.md:479)). If core hands the CLI a struct full of cleartext claim values, every present and future frontend has to *remember* to redact, and one forgotten path leaks. The prototype tests whether a `ClaimValue` newtype that redacts on `Serialize`/`Display` and requires an explicit `.reveal()` (the `secrecy` pattern) is workable — that makes the safe default a compile-time property instead of a discipline. It also forces the "low entropy → mask, not hash" heuristic to become real code: on what basis, without a schema? JSON type? value length? An enumerated list of known-low-cardinality claim names?

**4. Where does the `CredentialFormat` / `ProofSuite` seam fall when the proof *is* the container?**
JWT is the case that stresses the split, which is exactly why it's the right prototype. In JSON-LD DI the proof is a field inside the document and the split is obvious; in VC-JWT the JWS envelope *is* the format. Does `CredentialFormat::parse` yield something that hands a detached payload+signature to `ProofSuite::verify`, or does the JWT format own verification end to end and `ProofSuite` only means something for DI? Getting this wrong is the retrofit §7 is trying to avoid. Secondary but concrete: are the traits object-safe? `vcrd formats` / `vcrd suites` implies a runtime registry, which implies `dyn`, which forbids generic methods and constrains associated types.

**5. Can any existing JOSE crate meet §10, or does vcrd have to own the JWS layer?**
§16 item 16 leaves this open with `josekit` as the only candidate with ES512 coverage and unvetted maturity. But the real question is bigger than coverage. §10 requires an unsupported algorithm to fail *by name*, and a caller allowlist rejection to be a *distinct* diagnosis from unsupported ([REQUIREMENTS.md:643](REQUIREMENTS.md:643)). Most JOSE crates collapse both into one opaque error, and several pick the algorithm from the attacker-supplied header rather than from caller policy. If no crate can express those three states distinguishably, vcrd owns JWS parsing, the JWK→verifying-key mapping for every curve, and the algorithm registry — a materially larger initial scope than "add a dependency." That's an architecture answer, and it's cheap to get from a spike.

**6. What is the key-provenance rule, and does the result schema need to express it?**
For a JWT VC, key material can come from an embedded `jwk` header, a `kid`, `did:key` in `iss`, or the `issuer` field. Honoring an embedded `jwk` without pinning it to an independently-established issuer key is a verification bypass — the attacker signs with their own key and ships the matching public key. The prototype forces the precedence rules to be written down, and surfaces the question of whether "verified against credential-supplied key material" vs. "verified against independently-resolved key material" needs to be a distinct field in the v1 result. If it does, it has to be there from the start. Adjacent: `did:key` is multibase/multicodec decoding, and any mismatch between the curves your JOSE layer verifies and the codecs you can decode is a gap you'd rather find now.

**7. For VC-JWT, what does "validate" even check?**
Genuinely ambiguous, and §4's tier model doesn't settle it. VC-JWT carries both registered JWT claims (`iss`, `nbf`, `exp`, `jti`) and data-model fields; in the 1.1 mapping they're duplicated and can disagree — which is authoritative? Under VCDM 2.0 / VC-JOSE-COSE the picture is different. This is also how you decide §10's deliberately-unpinned "which JWT format first" question: the prototype *is* the mechanism for answering it, and I'd expect the answer to be VC-JOSE-COSE rather than the 1.1 mapping. Coupled to this: is `exp`/`nbf` checking validate (no crypto, no network — fits tier 2) or verify? That choice changes the exit-code contract, and it drags in §16 item 17's clock-skew decision.

## Answered cheaply as a side effect

- **The injection ergonomics.** Clock, RNG, DID resolver, context loader, HTTP trust anchor, algorithm allowlist, expected challenge/domain — that's seven injected things converging on one entry point. Does every call take seven parameters, or is there a context struct? And since core may not call `SystemTime::now()`, is there *no* default clock — meaning every frontend supplies one, or core ships a `SystemClock` behind a feature flag?
- **Structural limits.** §6 wants defaults "derived from measurement, not guessed" — the prototype is where you measure. Also whether plain `serde_json` can enforce a nesting-depth cap at all, or whether that forces a custom deserializer.
- **Exit-code taxonomy** and what `--verbosity 0` means when the answer is partial success.
- **Feature-gate plumbing** — does `--no-default-features --features jwt-vc` compile clean, and does the `formats`/`suites` registry behave under arbitrary feature combinations? Cheap now, tedious later.

## What it won't answer — don't scope it in

Whether `ProofSuite` truly accommodates selective disclosure (one suite can't stress that; a second cheap probe at SD-JWT's disclosure array would tell you far more than anything JWT-only can). Anything about RDF canonicalization, which shares almost nothing with the JOSE path. Whether the differential oracles agree. Anything on the OpenID4VP/live-verifier side.

## Shape I'd suggest

Go all the way to rendered output — bytes → parse → validate → verify → both `text` and `json`, with real exit codes. Questions 1–3 and 7 simply don't appear if the spike stops at `signature_valid: true`; the cross-cutting decisions only surface at the output boundary.

And build the negative cases first, not the happy path: alg-confusion (`alg: none`, HMAC-with-public-key), an embedded-`jwk` credential, expired, tampered signature, unsupported-but-real algorithm, supported-but-allowlist-rejected. The happy path answers almost nothing — every design question above is stressed by failures, and those six fixtures exercise §11's required categories while doubling as the beginning of your curated example library.

The one thing worth keeping from a throwaway is the answers. §16 is already the canonical record of open items, and a spike that closes items 16 and 17 and adds decisions on result shape, redaction placement, and key provenance is worth more than the code that produced them.
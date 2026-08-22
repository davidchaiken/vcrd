# Plan: Sequence of sessions to revise REQUIREMENTS.md

## Context

[REQUIREMENTS-REVIEW.md](../../code/vcrd/REQUIREMENTS-REVIEW.md) reviewed
[REQUIREMENTS.md](../../code/vcrd/REQUIREMENTS.md) and raised recommendations across product
positioning, security, and ethics/legal. Since the review, the user completed a hands-on
evaluation of the verifiable-credentials tooling ecosystem (didkit, ssi, isomdl, openid4vp,
Credo-TS, vc-js-cli, Veramo, walt.id, EUDI verifier-endpoint, anoncreds-rs, plus grounding
checks on the review's own claims), fully recorded in
[requirements-review-handoff.txt](../../code/vcrd/requirements-review-handoff.txt). Several
review recommendations are now settled decisions rather than open questions (e.g. no direct
`ssi` dependency, ever); others remain genuinely open and need a decision made *during* the
session that edits that section, not before.

This plan enumerates a sequence of self-contained editing sessions, each targeting specific
REQUIREMENTS.md sections, so each can be run independently with clear scope. Per the user's
request, the sequence starts with the Related Work section (the originally-planned first step,
now unblocked by the finished evaluation) and is otherwise ordered so that decisions which
constrain later sections (network taxonomy, ICP prioritization) come before the sections that
depend on them (vcrd-net/mobile-wallet scoping, format priority).

No editing happens in this planning session — this file is the deliverable.

## Steps

### 1. Write the Related Work section
**New section**, placed after §2 (Background) or as a subsection of it — renumbers everything
after it, so do this first.

Content, drawn entirely from the handoff appendix (already hands-on verified, not just review
claims): didkit's archival (July 2025) and successor-vacuum positioning; `ssi` as
actively-maintained but SpruceID-mDL-business-owned; isomdl (ships own fixtures, undercuts the
mdoc test-vector-licensing deferral rationale); openid4vp; Credo-TS, vc-js-cli, Veramo, walt.id,
EUDI verifier-endpoint, anoncreds-rs (one paragraph each — completeness/usability/diagnosability
framing, not a pass/fail matrix, per how the handoff itself frames the survey's goal); the
grounding check on IOTA identity/indy-vdr/Aries `vcx` (active but wrong-shaped, sharpening the
review's "no successor" claim rather than repeating it); TBD's `ssi-sdk`/web5 and the official
W3C/OIDF conformance suites, both explicitly scoped out with the reasoning on record (the latter
is also a candidate oracle — cross-reference step 2).

Position vcrd explicitly as filling the gap left by didkit's archival (review recommendation
#1), courting its orphaned users.

### 2. Dependency/interop positioning
**Target: §5 (dependency policy bullet), §14 item 1 (`ssi` evaluation)**

Write in the settled decision: no direct dependency on `ssi`, `openid4vp`, `isomdl`, or any
other ecosystem VC/OIDC4VP library in `vcrd-core`'s `Cargo.toml` — interop is demonstrated via a
differential-testing harness, not coupled via a shared dependency. This sharpens the review's
§2.7 suggestion (differential testing as a cheap correctness check) into the actual
interop-positioning story, and converts §14 item 1 from an open question into a closed one
(replace "evaluate `ssi`... is any part worth depending on" with the decision and its
rationale). Add differential testing as a named category in §10 (Testing Strategy), listing the
tools hands-on-validated as viable oracles this session (openid4vp, walt.id, EUDI
verifier-endpoint) and the two out-of-scope-for-now candidates from step 1 (W3C/OIDF conformance
suites, TBD ssi-sdk) as future oracle candidates.

### 3. Decide: coding agents as primary ICP, or one of three co-equal audiences
**Target: §1 (Goals/audiences), §5 (candidate new principle: "flags over prompts,
non-interactive by default")**

This is a real decision to make in this session, not just documentation — flagged in the
handoff as unresolved and as something that would change how steps 6 and 8 below get decided
(format priority, diagnosability framing). Evidence to weigh is already on record: Veramo's
flat-boolean verify output and interactive-only CLI (sharpest diagnosability counter-example),
walt.id's fully-scriptable no-prompts REST API as the positive counterexample, and the
Infura-key/telemetry findings as a case for structural (not advisory) safety. Do this before
step 6, since format priority is easier to decide once the target user is settled.

### 4. Network taxonomy refinement
**Target: §5 (read-only/no-network principle), §7 (CLI flags), §8 (Input/Output Modalities)**

Replace the current binary "no-network by default" framing with the three-tier taxonomy settled
in discussion: (a) fully offline, (b) opens a local listener with no outbound call, (c) requires
real network reachability (tunnel/port-forward/proximity channel). Decide and document whether
(b) gets its own explicit opt-in flag distinct from `--allow-network`, per the handoff's
reasoning that inbound exposure is a materially different risk shape than outbound resolution.
This is concrete and self-contained but must land before step 7, since the mobile-wallet
live-verifier feature is exactly a tier-(b)/(c) case.

### 5. VC example library scoping
**Target: §10 (Testing Strategy) or a new subsection**

Small, self-contained. Scope a curated library of example/test verifiable credentials
(didkit's self-signed-credential pattern as the model) serving both conformance testing and
onboarding/learning use cases.

### 6. Format-priority decision
**Target: §9 (Initial Format & Verification Scope)**

Needs an actual decision in-session, not just documentation of the review's suggestion:
JWT-based format (or SD-JWT VC directly) before JSON-LD Data Integrity, per the review's
implementation-effort and market-direction argument. Also revisit mdoc's deprioritization: the
isomdl finding (ships its own fixtures, doesn't need official ISO test vectors) undercuts §9's
current test-vector-licensing rationale for deferring it — decide whether mdoc moves up, and if
not, restate the deferral reasoning without the now-undercut licensing justification. Benefits
from step 3's ICP decision being settled first (agent-primary favors JSON output correctness and
the JOSE path over RDF tooling).

### 7. vcrd-net decision + mobile-wallet live-verifier feature
**Target: §6 (workspace layout — `vcrd-net` deferred member), §8 (Input Modalities), §9
(Presentation support), §14 (Open/Deferred Items)**

The biggest step; do it after 4 (network taxonomy) and 6 (format priority) are settled, since it
depends on both. Decide whether to drop `vcrd-net` (review recommendation, ethical/legal
grounds — wiretap-adjacent framing, thin legitimate-use case since credential exchange rides
inside TLS) or keep it explicitly caveated, and whether to scope in its place a protocol-level
live-verifier feature: request a real presentation from a mobile wallet (motivating example: a
CA mDL) via QR code plus a local server or public tunnel, in the shape validated hands-on this
session against openid4vp/walt.id/EUDI verifier-endpoint. Document the real external limit
found during evaluation: government-grade wallet trust is gated by ecosystem accreditation
(AAMVA Digital Trust Service / IACA trust lists), not just a valid TLS cert — state this as a
boundary, not a solvable engineering problem. Per the user, the vcrd-net removal decision itself
is low-stakes/reversible; the mobile-wallet feature scoping is the substantive part of this
step.

### 8. Diagnosability principle + JOSE algorithm-coverage requirement
**Target: §5 (new principle, alongside graduated success), §9 or §11 (crate-selection note)**

Extend §5 with diagnosability as a named principle: failures should structurally pin down which
pipeline tier failed, whose side it's on, and why — not require the caller to hand-decode tokens
against spec text. Cross-reference review item 2.4 ("what was not checked" should be
first-class) as related but distinct. Add the concrete, evidenced sub-requirement: JOSE
algorithm support should be as broad as practical across the standard algorithm set, and fail
by-name (naming the unsupported algorithm and what is supported) rather than with an opaque
parse error — evidenced directly by ES512/P-521 blocking an EUDI interop round-trip against two
of three Rust JOSE crates tested. Add a crate-selection note (josekit confirmed to have full
ECDSA-family coverage on paper, maturity not yet vetted) wherever the JOSE dependency actually
gets chosen — likely a new §14 open item rather than a decision now.

### 9. Remaining Security Review items (§2.1–§2.6)
**Target: §11 (Security Posture, primarily the threat model), with touches to §5, §7, §9**

Work through each item not yet engaged, in review order:
- 2.1 JSON-LD context substitution — name explicitly in the §11 threat model alongside
  algorithm confusion; state that verification against an unpinned/unknown context must be a
  distinct, loudly-reported condition even under `--allow-network`.
- 2.2 Canonicalization complexity / poison-graph bound — extend §5's structural-limits bullet
  to explicitly require a bounded canonicalization step (iteration/permutation budget, fail
  closed).
- 2.3 "Verified" without status-checking — extend §5's graduated-success principle and §11 so
  the result model enumerates what was *not* evaluated (revocation, context resolution,
  holder-binding) with equal prominence to what passed. Cross-reference step 8's diagnosability
  principle — related but distinct, per the handoff.
- 2.4 VP replay/challenge-binding — §9's presentation-support paragraph gets optional
  expected-challenge/domain parameters in v1 of the verify API, with an explicit
  "holder-proof valid, replay-binding not evaluated" report when absent.
- 2.5 Minimum network-hardening bar — §11, scoped to the tier-(c) case from step 4:
  HTTPS-only + cert validation, response size caps, redirect limits, SSRF stance for
  `did:web`/tunnel-reachable resolution.
- 2.6 Redaction-aware output / PII stance — §7 (verbose output semantics) and §11; document what
  `--verbose` may emit and consider a redaction-aware output mode.

### 10. Ethical/legal: reliance and liability disclaimer
**Target: §11 (SECURITY.md bullet), note for README (outside REQUIREMENTS.md scope, flag only)**

Add the plain-language "pre-1.0, not for production trust decisions" stance to the SECURITY.md
description in §11, reinforcing §1's existing non-goal statement rather than duplicating it.

### 11. Community-presence contribution strategy
**Target: §13 (Contribution & Community Structure)**

Add the review's community-presence funnel (W3C Credentials Community Group, registering vcrd
in the W3C VC test suites, interop/plugfest participation, filing spec issues) as the primary
contributor-acquisition strategy, distinct from and prioritized above the repo-hygiene items
(§13 already covers CONTRIBUTING.md/templates/CoC) that are necessary but insufficient on their
own.

### 12. Style checks

* Remove words or phrases like "authentic, real, genuine, or to be honest" that seek to give the reader an emotional feeling of trust without significantly adding to the technical content.
* Remove words like "full stop" or "period" that emphasize a point without adding to the technical content.
* Ensure that REQUIREMENTS.md does not refer internally to previous versions of itself. It should read as a specification for what should be built in the future, not as a conversation over time about what should be built in the future.
* Ensure that domain-specific acronyms (e.g. VP) are expanded when they first appear in the document. Wider-scope acryonyms (e.g. HTTPS, RFC) do not necessarily need to be expanded. Ask the user if there are any gray areas.

### 13. Final consistency pass
Re-read the full revised REQUIREMENTS.md against REQUIREMENTS-REVIEW.md §4's seven-item
recommendation summary to confirm each is addressed or explicitly deferred with reasoning; fix
cross-references and section numbers -- especially the ones disturbed by the new Related Work section from step 1.

## Verification
This is a documentation-editing sequence with no code to run. Verification per step is a
re-read of the edited section(s) against: (a) the specific review passage(s) it addresses, and
(b) the corresponding handoff paragraph(s), confirming no unverified claim is written in as
settled fact (e.g. the walt.id "still-open" bug status correction, the isomdl fixture-licensing
finding) and that each open decision is actually decided in-session rather than re-deferred
silently. Step 12 is the final check across the whole document.

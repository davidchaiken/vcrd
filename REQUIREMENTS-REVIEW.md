# Review of the vcrd Requirements & Design Document

Reviewer perspective: senior product/engineering feedback on strategy, market fit, and
security posture. This review deliberately skips editorial detail and focuses on
design-level questions. Overall assessment first: this is an unusually disciplined design
document — the dependency-injection discipline, the no-panic policy, the CI hardening
section, and the named-negative-fixture requirement are all things most projects retrofit
after an incident. The main risks are strategic (format priority, differentiation from
incumbents) and a handful of security gaps that sit exactly at the seams the document
draws around itself.

## 1. Product Value & Positioning

**The niche is real — and, as of 2025, genuinely vacant.** The identity ecosystem has
plenty of *libraries* (SpruceID's `ssi`, Digital Bazaar's JS stack, the EUDI reference
libraries, aries/AnonCreds stacks) and plenty of hosted *platforms*, but nothing
maintained today filling the role `openssl x509 -text`, `step certificate inspect`, or
`jwt-cli` play for their domains: a local, safe-by-default, scriptable inspector. The
closest thing that existed — SpruceID's `didkit` CLI — was archived in July 2025 when
SpruceID stopped using it internally, and walt.id likewise discontinued its
general-purpose SSI Kit in 2024 in favor of a server-oriented stack. A survey of the
Rust ecosystem (ledger-tied stacks like IOTA identity and indy-vdr, the Aries-focused
`vcx`, format-translation tools) turns up no successor. Two consequences follow. First,
there is an orphaned user base: anyone with `didkit` in a script or CI pipeline needs a
replacement, which is both a concrete early-adopter audience and a contributor funnel.
Second, a caution: commercial vendors keep abandoning exactly this kind of tool because
it doesn't generate revenue — evidence the market is real but narrow, and that vcrd's
sustainability model (community-maintained, no revenue requirement) is actually the
right fit for the niche, the way jq/ripgrep/age are maintainer-driven rather than
product-line-driven.

**The `ssi` question is now purely a dependency question — with concentration risk.**
With `didkit` gone, `ssi` (still actively maintained: releases in Feb and Apr 2026,
~178k downloads) is no longer a competitor, which simplifies §14.1: evaluate it on
dependency merits alone. But SpruceID's business is now visibly government mDL
deployments (the California DMV program, NIST NCCoE membership), and `ssi` is maintained
as internal infrastructure for that product line. The didkit archival shows what happens
to SpruceID code that stops serving that mission. If vcrd depends on `ssi` for anything
load-bearing (DID resolution, canonicalization), §5's dependency policy should
explicitly price in that risk and keep trait boundaries clean enough that swapping it
out later is feasible. Concretely, "clean" means `ssi` lives entirely behind vcrd's own
injectable traits as one implementation of them, with none of its types — error enums,
credential structs, trait bounds — leaking into `vcrd-core`'s public API. That way,
replacing it later (with a fork or an in-house implementation) is a one-module change
rather than a breaking change for every consumer of `vcrd-core`.

**Format priority deserves a hard second look.** The document starts with JSON-LD + Data
Integrity "because it keeps the first implementation understandable and testable." In
practice JSON-LD Data Integrity is the *hardest* of the listed formats — RDF
canonicalization (RDFC-1.0) is a substantial, subtle machine, and it is the format whose
ecosystem share is arguably declining. Meanwhile SD-JWT VC and mdoc/mDL are where
real-world adoption is heading, driven by eIDAS 2.0, the EU Digital Identity Wallet
(whose reference implementation ships SD-JWT and mdoc libraries), and US-state mDL
programs (California alone has issued millions of mDLs, accepted at hundreds of TSA
checkpoints). The mdoc deprioritization for ISO-licensing reasons is defensible, but
consider inverting the JWT ordering: a JWT-based format (or SD-JWT VC directly) first is
less code, exercises the JOSE verification path the threat model already worries about,
and reaches the users who exist today. And since mdoc is the single fastest-growing
format, the test-vector licensing obstacle is worth actively working around (synthetic
fixtures, interop-event vectors) rather than accepting as an indefinite deferral.

**Likely user profiles:** wallet and issuer developers debugging why a credential fails
elsewhere; standards implementers and interop-plugfest participants who need a neutral
second opinion; security researchers auditing credential deployments; CI pipelines and AI
agents needing structured verdicts; educators demonstrating the data model. Notably,
several of these are *diagnostic* users — which argues for investing early in the quality
of failure explanations (which the design already prioritizes) over breadth of formats.

**Contribution motivation:** the trait-based extension points and welcoming platform-gap
framing are right, but contributors come from *community presence*, not repo hygiene.
The highest-leverage move is showing up where this community already works and being the
tool people reach for there. Concretely, in ascending order of effort:

- Join the W3C Credentials Community Group (open to anyone, no membership fee) — the
  mailing list and weekly calls — and mention vcrd when relevant threads come up, e.g.
  someone debugging a credential that fails verification elsewhere.
- Register vcrd as an implementation in the W3C VC test suites; the conformance reports
  are public, and appearing in them is how spec editors and implementers discover that a
  tool exists.
- Participate in interop events (JFF/VC-EDU plugfests, DIF interop profile work), where
  dozens of wallet and issuer vendors test against each other and constantly need a
  neutral third opinion on "whose bug is this?" — a tool that answers that question
  earns adoption in an afternoon.
- File spec issues when implementation work uncovers ambiguities. Implementers who file
  good issues become known quantities, and their tools inherit that credibility.

That's a contributor funnel no CONTRIBUTING.md can substitute for: contributors don't
find projects through repo files, they find them because the maintainer was visibly
useful in a venue they already frequent.

## 2. Security Review

The existing posture is strong: a written threat model, algorithm-confusion attacks as a
named test category, structural resource limits, `forbid(unsafe_code)`, and a CI-hardening
section that is better than most mature projects'. The gaps below are mostly at the
boundaries the document draws.

**2.1 JSON-LD context substitution is missing from the threat model.** This is the most
important omission. In JSON-LD credentials, the `@context` controls the *meaning* of every
term in the document. A signature over canonicalized RDF can remain valid while a
manipulated or attacker-hosted context silently changes what the claims mean — a
documented attack class against Data Integrity verifiers. The design's vendored context
cache is the right mechanism, but the policy needs stating: verification against an
unknown or non-pinned context must be a distinct, loudly-reported condition, not a silent
fetch-and-proceed (even under `--allow-network`). Name this in §11 alongside algorithm
confusion.

**2.2 Canonicalization complexity breaks the "cost scales with input size" assumption.**
RDF canonicalization has pathological cases ("poison graphs") whose cost is
super-polynomial in graph structure, not linear in bytes. §5's structural limits (size,
depth, iteration count) are the right shape, but the document should explicitly require a
bounded canonicalization step — an iteration/permutation budget that fails closed —
because this is the one place where the "core is fast by construction" principle can be
defeated by a small input.

**2.3 "Verified" without status checking is a false-assurance trap.** Revocation/status
(Bitstring Status List and kin) is network-dependent and therefore off by default — fine.
But the output contract must then make *non-checks* first-class: a verify result should
enumerate what was **not** evaluated (revocation not checked, context not resolved,
holder-binding not evaluated) with the same prominence as what passed. Humans — and
downstream tools, including the future trust layer — will otherwise read "verified: true"
as "trustworthy," which is precisely the misreading the §1 non-goal is trying to prevent.
This belongs in the core result model, not frontend copy.

**2.4 Presentation verification needs protocol inputs, not just cryptography.** A VP's
holder-proof is only meaningful against a verifier-supplied challenge/nonce and
domain/audience; without checking those, a replayed presentation verifies perfectly. This
is not trust-layer judgment — it's protocol correctness — so `verify` on a VP needs
optional expected-challenge/domain parameters in v1 of the API, and must report
"holder-proof cryptographically valid, replay-binding not evaluated" when they're absent.
Retrofitting this into the result schema later would be disruptive.

**2.5 Network-mode hardening can't be fully deferred.** §11 defers network-facing threats,
but `--allow-network` and `did:web` are in the initial scope, so a minimal hardening bar
is needed now: HTTPS-only with certificate validation, response size caps, redirect
limits, and an SSRF stance (`did:web` resolution can be pointed at internal
hosts/link-local addresses — a real concern the moment vcrd runs inside CI or server-side
tooling). A short "network minimum bar" subsection would close this without pulling the
full network threat model forward.

**2.6 Credential contents are sensitive data; the tool's own output is a leak surface.**
The issue-template norm against pasting live credentials is good, but vcrd itself will
happily print full claim sets — including PII and, for SD-JWT, disclosed values — into
terminals, CI logs, and agent transcripts. Consider a redaction-aware output mode (claim
names and structure without values) and a documented stance on what `--verbose` may emit.
This is both a security and an ethics item.

**2.7 Cheap additions:** differential testing against the `ssi` crate (and/or the EUDI
reference libraries for SD-JWT) — feed the identical credential to both vcrd and the
independent implementation and compare verdicts. Whenever the two disagree, one of them
has a real bug, and the disagreeing fixture pinpoints it; this is cheap precisely
because the other implementation serves as the oracle — no one has to hand-derive the
expected answer, and unlike a fuzzer crash or a hand-written test, a disagreement
between independent implementations of the same spec is almost never noise. Also: an
algorithm-allowlist policy input for verification (the verifier, not the credential,
should decide acceptable algorithms — the generalization of the alg-confusion defense);
and an explicit clock-skew tolerance policy for expiry/not-before checks, since the
injectable clock settles testability but not the CLI's default semantics.

## 3. Ethical & Legal Considerations

- **`vcrd-net` is casually named but ethically and legally loaded.** A tcpdump-style
  capture tool for *identity credentials* is an interception tool: wiretap/lawful-intercept
  statutes and GDPR apply, and the legitimate use case is thin since credential exchanges
  ride inside TLS anyway. Recommend either dropping it from the document or adding an
  explicit note that it would require its own ethics/legal review before design begins.
- **Reliance and liability:** people will make real decisions based on vcrd's output. The
  MIT/Apache warranty disclaimers cover the legal floor, but a plain-language "pre-1.0,
  not for production trust decisions" statement in README/SECURITY.md is cheap and honest.
- Already handled well: fixture licensing provenance (§10), the ISO test-vector licensing
  problem, the Codecov-style supply-chain lesson, and the Code-of-Conduct
  secondary-contact problem for a solo project — the last of these is a detail most solo
  maintainers never think about.

## 4. Summary of Recommendations

1. Position vcrd explicitly as the successor to the archived `didkit` CLI and court its
   orphaned users; evaluate `ssi` (§14.1) purely as a dependency, pricing in the risk
   that SpruceID's mDL-focused business stops maintaining it.
2. Reconsider format order: a JWT-based format (ideally SD-JWT VC) before JSON-LD Data
   Integrity better matches both implementation effort and market direction, and treat
   the mdoc test-vector licensing problem as one to solve, not just note.
3. Add to the threat model: context substitution, canonicalization complexity bounds,
   VP replay/challenge binding, and a minimum network-mode hardening bar.
4. Make "what was *not* checked" a first-class part of the core result model.
5. Add a redaction-aware output mode and a stance on PII in diagnostics.
6. Remove or explicitly caveat `vcrd-net`.
7. Invest in community presence (CCG/DIF, plugfests) as the primary contributor funnel.

None of these undermine the foundation — the core principles (no-network by default,
explicit dependencies, graduated results, UI-agnostic core) are the right ones and are
stated with rare precision. The project is well positioned to proceed to implementation
once the threat-model additions above are folded in.

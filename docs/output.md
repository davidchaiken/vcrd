# vcrd's output

`vcrd` prints its result on standard output in one of three formats, and writes caller
errors and warnings to standard error (REQUIREMENTS §8). This page explains how to read a
result. It grows as the output does; [ARCHITECTURE.md §6](../ARCHITECTURE.md) lists every
key of the JSON envelope.

The JSON schema is unstable until `schema_version` is no longer `0`: keys and values may
change between releases.

## Formats

| `--format` | What it prints |
|---|---|
| `text` (the default) | the result as labeled sections of tables, for a reader at a terminal |
| `plain` | one line per item, for line-oriented tools: `name: value` for a single value, and `name: column=value …` for a row of a table, such as `phases.verify: outcome=failed findings=verify.proof_expired` |
| `json` | the complete result as one JSON document (REQUIREMENTS §9), whatever the verbosity level |

The names in `plain` are the JSON keys and paths the values come from. A value in a
`column=value` pair is quoted as a JSON string when it is empty or contains a space, an
`=` or a quote. In `text` and `plain`, every control character and every character that
reorders bidirectional text is printed as an escape such as `\u{001b}`, so that a
credential's content cannot act on the terminal or disguise what surrounds it.

## Verbosity

`--verbosity` (0 to 3, default 1) chooses how much `text` and `plain` show. JSON is
complete at levels 1 to 3.

| Level | `text` and `plain` show |
|---|---|
| 0 | nothing, in any format, on either stream: the exit code is the whole answer. `--unsafe` has no effect, since nothing is shown. |
| 1 | the status; the credential's kind, issuer, types, and validity with its bounds; inspect's outcome, kinds of finding and what blocked it; when verify was requested, the same for verify, and each proof's suite, algorithm, outcome and own validity, which kind of key the deciding proof key is (`key_provenance.source` and `method`) and its thumbprint, and the embedded key, if any: where it is, whether it is the issuer key, and its proof's result; the claims, masked; every error and warning, and how many `info` findings were left out; and the checks not evaluated |
| 2 | everything except the credential's metadata. Level 1, plus: the exit code; the input's size and depth; the format and profile; the parse phase; the JWK of the deciding proof key, and the thumbprint and JWK of the embedded key; the header; and the `info` findings |
| 3 | everything: level 2, plus the credential's metadata |

An `info` finding never fails a phase, and one appears on most credentials in use today:
`verify.algorithm_deprecated`, for the `EdDSA` that RFC 9864 deprecates. So level 1
leaves the `info` findings out of the findings and of each phase's kinds of finding, and
says how many it left out: in `text`, a Not shown line under Findings, and in `plain`,
`findings: 1 info finding (see --verbosity 2)`. A finding in `plain` keeps its index in
the JSON `findings`, so the first one shown may be `findings[1]`.

At every level, `text` gives a few values as a phrase, where `plain` gives the values the
phrase is made of, one per line, as JSON names them:

| `text` | Example | `plain` |
|---|---|---|
| Credential validity | `current, 2026-01-01T00:00:00Z to 2031-01-01T00:00:00Z` | `credential.validity`, `valid_from`, `valid_until` |
| Deciding proof key | `issuer key, from did:key` | `key_provenance.source`, `method` |
| Embedded key | `header.jwk: a different key; proof correct` | `key_provenance.embedded_key.location`, `same_as_issuer_key`, `proof` |

The summary's validity is labeled Credential validity because a proof has its own,
labeled Validity in the Proof section: the JWT's `nbf` and `exp`, which can expire while
the credential is current.

At levels 1 to 3, a caller error's message is written to standard error as well as
reported in the result. A parse failure is shown at level 1 by the later phases'
`blocked_by`, which names parse.

## Masked values and `--unsafe`

Claim values are masked by default (REQUIREMENTS §8). `--unsafe` shows them:

| Flag | Shown in cleartext |
|---|---|
| none, or `--unsafe=0` | metadata only |
| `--unsafe`, `--unsafe=1` or `--unsafe 1` | metadata and claims |
| `--unsafe=2` or `--unsafe 2` | metadata, claims, and cryptographic secrets, such as the private-key members of a `jwk` the credential carries |

A level is read after `--unsafe` only when it is `0`, `1` or `2`, so `vcrd --unsafe f.jwt`
means level 1; a file with one of those names is written `./2`.

With `--unsafe=1` or `=2`, a warning says what is shown, on standard error and in the
result, so that a reader of standard output alone sees it too. In JSON it is an entry in
`warnings`, `{code, message}` with code `unsafe`. `text` prints it in a Warnings table,
and `plain` as `warnings[0]: code=unsafe message="…"`, both after the findings: in
`text` and `plain` the first line is always the status.

## Values and their visibility

The credential's claims (`credential.claims`), its metadata (`credential.metadata`) and
the header (`format.header`) are each a list of values, one per JSON scalar, in input
order:

| Key | Present | Value |
|---|---|---|
| `path` | always | where the value is, such as `credentialSubject.degree.name` or `jwk.d` |
| `type` | always | its JSON type: `string`, `number`, `bool` or `null` |
| `visibility` | always | whether it is sensitive and, if so, whether it is shown; see below |
| `value` | unless masked | the value |

| `visibility` | Meaning |
|---|---|
| `non_sensitive` | metadata, such as an issuer, a type or a date: always shown |
| `masked` | a claim, or a cryptographic secret, not shown |
| `revealed` | a claim or a secret shown because `--unsafe` asked for it |

`text` shows the same in a Visibility column, with `(masked)` in place of a masked value,
and `plain` adds `visibility=…` to each value's line. A secret stays `masked` at
`--unsafe=1`, while the claims beside it are `revealed`.

Every revealed value is also listed in `reveals`, as `{path, location, visibility}`, so
that a script can tell whether anything was revealed without reading every value.
`location` is the key the path is relative to: `credential.claims` or `format.header`;
`visibility` is `revealed`, as on the value itself.

## `format.header`

The securing mechanism's header: for VC-JOSE-COSE, the JOSE header, every member
included, listed as values as the claims are. A member whose name is repeated is listed
once for each occurrence. The list is empty when the input has no header or it did not
decode. `text` and `plain` show the header from level 2. In `text`, a `kid` that is a DID
URL is broken onto two lines before its fragment (`#`), since the DID part alone is as
wide as most terminals allow; `plain` keeps it on one line.

## `status` and `exit_code`

| `status` | `exit_code` | Meaning |
|---|---|---|
| `passed` | 0 | every requested phase passed |
| `caller_error` | 1 | vcrd could not run as asked: an invalid flag, an unreadable file. `error` holds a code and a message, and no phase ran. |
| `parse_failed` | 2, 5 or 6 | the earliest failed phase is parse |
| `inspect_failed` | 3, 5 or 6 | the earliest failed phase is inspect |
| `verify_failed` | 4, 5 or 6 | the earliest failed phase is verify |

No output setting changes the exit code: whatever the format, the verbosity level or
the `--unsafe` level, it is the result's.

`status` names the earliest failed phase. `exit_code` is 6 when any error finding is
attributed to vcrd (something vcrd does not support), otherwise 5 when any is attributed
to the caller's policy (such as a size limit), and otherwise the code of the earliest
failed phase. `status` alone cannot say "expired but correctly signed"; `phases` can.

## `phases`

One object for each of `parse`, `inspect` and `verify`, always in that order:

| Key | Present | Value |
|---|---|---|
| `outcome` | always | what happened to the phase; see below |
| `findings` | always | the kinds of condition this phase found: each finding code once, in the order first found. The top-level `findings` list has every occurrence, with its attribution, severity and detail, such as which segment or which member it concerns. |
| `blocked_by` | when `outcome` is `not_reached` because of an earlier phase | why the phase did not run; see below |

### `outcome`

| Value | Meaning |
|---|---|
| `passed` | The phase ran and found no error. It may have found warnings or information. |
| `failed` | The phase ran and found at least one error. |
| `not_requested` | The operation does not include this phase: `vcrd inspect` does not verify. |
| `not_reached` | The phase was requested and did not run. `blocked_by` says why, except after a caller error, when no phase ran and `blocked_by` is absent. |

A failed phase does not stop the next one unless running it is impossible or dangerous
(REQUIREMENTS §4). A credential can fail inspection and still have a sound signature, and
`verify` then reports it.

### `blocked_by`

| Key | Present | Value |
|---|---|---|
| `phase` | always | the phase whose findings prevented this one: `parse` or `inspect`. That phase's own `findings` say what was wrong. A block by `parse` means parse failed: whatever the cause, nothing that fails to parse can be inspected or verified. |
| `reason` | always | `impossible`: what the phase needs is not available. `dangerous`: running it could expose vcrd to an exploit, or would fetch material such as a key from an untrustworthy source. No input produces `dangerous` yet. |
| `missing` | when `reason` is `impossible` and the blocking phase is not `parse` | what the phase lacks: `key_material` |
| `consulted` | when `missing` is `key_material` | the key sources vcrd considered, none of them usable; values below |

| `missing` | Meaning |
|---|---|
| `key_material` | No key can be found to check the signature with. The credential names no usable issuer identifier (no `issuer`, or one that is not a URL, or an encoding vcrd does not read), and no other source of keys is available. A credential that carries a key about itself is not blocked: verify runs and reports that it refused that key (`verify.embedded_key_refused`). |

| `consulted` value | The source |
|---|---|
| `issuer_identifier` | a key derived from the issuer identifier the credential names, such as a `did:key` |
| `caller_supplied` | keys the caller passes in (not available yet) |
| `credential_embedded` | a key the credential carries about itself, which vcrd uses only if the caller opts in (not available yet) |

The list may gain values; a consumer should accept values it does not recognize.

`text` and `plain` say the same in the Blocked by column, in the reader's terms: "parse
failed", or "inspect: no key for verify; looked in: issuer identifier".

## Keys and proofs

A result can involve more than one key. These terms say which, here and in
[findings.md](findings.md); [ARCHITECTURE.md §8](../ARCHITECTURE.md), "Keys and proofs",
defines them in full:

| Term | Meaning |
|---|---|
| embedded key | a key the credential carries about its own proof, such as a JWS header's `jwk`; self-asserted |
| issuer key | the key the issuer identifier gives: for a `did:key`, the key it encodes |
| caller-supplied key | key material the caller passes in (milestone 2) |
| proof key | a key vcrd makes a proof with |
| deciding proof key | the proof key whose proof decides the outcome and the exit code |
| correct, incorrect, not attempted | a proof's result with one proof key: the signature holds for that key, it does not, or the check was not made |
| refused | a key vcrd will not let decide the outcome: a weak key, one that is not a signing key or of a type vcrd does not support, or an embedded key alone without the caller's opt-in |

The rules, which ARCHITECTURE.md §8 sets out as a table of every combination:

1. A caller-supplied key and an issuer key, when both are present, must be the same key.
2. The deciding proof key is the caller-supplied key or the issuer key. The embedded key
   decides only when neither is present, and then only with the caller's opt-in.
3. vcrd may succeed only when the deciding proof is correct.

A refused caller-supplied or issuer key prevents success; a refused embedded key is
treated as not present. The rules are necessary, not sufficient: an inspect error or an
expired signature still fails.

Where a result answers each question about its keys:

| Question | JSON and `plain` | `text` |
|---|---|---|
| Which kind of key is the deciding proof key? | `key_provenance.source` and `method`; absent when no key could decide | Deciding proof key |
| Does the credential carry an embedded key? | `key_provenance.embedded_key`, present when it carries one vcrd can read | Embedded key |
| Is the embedded key the issuer key? | `embedded_key.same_as_issuer_key`, absent when there is no issuer key; the two thumbprints | the same key, a different key, or no issuer key to compare with |
| Is the deciding proof correct? | `outcome` | Outcome |
| Is the proof with the embedded key correct? | `embedded_key.proof` | proof correct, incorrect or not attempted |

The findings that say what the keys and proofs show:

| Situation | Finding |
|---|---|
| The embedded key is not the issuer key. | [`verify.embedded_key_mismatch`](findings.md#verify.embedded_key_mismatch), a warning |
| The proof with the embedded key is correct and the deciding proof is not: key substitution. | [`verify.embedded_key_proof_correct`](findings.md#verify.embedded_key_proof_correct), a warning |
| An embedded key alone, without the caller's opt-in. | [`verify.embedded_key_refused`](findings.md#verify.embedded_key_refused), an error |
| A refused issuer key. | [`verify.weak_key`](findings.md#verify.weak_key), [`verify.did_key_not_for_signing`](findings.md#verify.did_key_not_for_signing) or [`verify.did_key_codec_unsupported`](findings.md#verify.did_key_codec_unsupported), errors |

## `proofs`

One object for each proof the input carries, whether or not verify ran:

| Key | Present | Value |
|---|---|---|
| `suite` | always | the proof suite, such as `jws` |
| `algorithm` | always | the algorithm the input declares, which vcrd checks and never obeys; `null` when there is none |
| `outcome` | always | the proof's result with the deciding proof key: `correct`, `incorrect`, or `not_attempted` (no key could decide, or the algorithm or the signature ruled out every proof; the findings say which) |
| `key_provenance` | always | where the deciding proof key came from, and the embedded key, if any (above); empty when verify did not run |
| `validity` | when verify ran | where the clock falls relative to the proof's own times: `current`, `expired`, `not_yet_valid`, `unbounded` (no times) or `unknown` (a time that is not a number). For a JWT these are `nbf` and `exp`, the times of the signature, separate from the credential's own validity period in `credential.validity` |

A proof can be correct and still have expired: `outcome` and `validity` are independent.

`key_provenance.embedded_key` has the embedded key's `location`, `thumbprint` and `jwk`;
`same_as_issuer_key`, absent when there is no issuer key to compare it with; and `proof`,
the proof's result with it as the proof key, which vcrd makes for information whether or
not the key can decide. `outcome: not_attempted` with `embedded_key.proof: correct`
means that the signature holds for a key vcrd refused to let decide (REQUIREMENTS §10).

Each key is named by its JWK Thumbprint (RFC 7638; REQUIREMENTS §15): the SHA-256, in
base64url, of its public members as a canonical JSON object. Beside the thumbprint is the
key itself as a JWK, those same members, so that a reader can see which key a thumbprint
names and compare two keys by eye:

| Key | What it names |
|---|---|
| `key_provenance.thumbprint`, `key_provenance.jwk` | the deciding proof key: for a `did:key` issuer, the key the identifier encodes |
| `embedded_key.thumbprint`, `embedded_key.jwk` | the embedded key, at `embedded_key.location`, such as the header's `jwk` |

An embedded key's private members, if any, are never part of its JWK here. Findings about
keys name them the same way: `key`, with its `source`, `method` and `thumbprint`, for the
issuer key or the deciding proof key, and `embedded_key`, with its `location` and
`thumbprint`, for the embedded key. `verify.weak_key` adds `criterion`, the weak-key test
the key fails: for Ed25519, `small_order`.

## `findings`

One entry for each condition found, in phase order. A phase's `findings` list names each
kind of condition once; this list has every occurrence.

| Key | Present | Value |
|---|---|---|
| `code` | always | the kind of condition, `<phase>.<condition>`, such as `parse.base64url_invalid` |
| `phase` | always | the phase that found it |
| `attribution` | always | its most probable origin: `input`; `policy`, a limit the caller can change; `vcrd`, something vcrd does not support; or `environment`, such as missing key material |
| `severity` | always | `error` fails the phase; `warning` and `info` do not |
| `detail` | always | the facts of this condition, tagged by `type`, such as which segment or which JSON path it concerns |

## `not_evaluated`

One entry for each check vcrd did not make, so that a result never reads as more than it
checked:

| Key | Present | Value |
|---|---|---|
| `what` | always | the check, such as `issuer_accreditation` |
| `why` | always | the reason, such as `not_implemented` |

[findings.md](findings.md#checks-not-evaluated) describes each check and each reason,
and what a result does not establish without the check. Below its table of checks,
`text` names that document and section: `Described in   docs/findings.md, section
"Checks not evaluated"`. `plain` prints `not_evaluated.<what>: reason=<why>` alone.

## Examples

The curated example in `text`, at the default level. Every phase passes, and the claims'
names are shown with their values masked. The example declares `EdDSA`, so it has one
`info` finding, which this level counts and level 2 lists.

```bash
vcrd verify examples/ed25519.jwt --now 2026-10-01T00:00:00Z
```

```text
 Status                passed
 Kind                  credential
 Issuer                did:key:z6MkpsLTxWPDwHepjwD5uTTUjkg9edkaFWqSMjejg6SPTv3N
 Types                 VerifiableCredential, ExampleDegreeCredential
 Credential validity   current, 2026-01-01T00:00:00Z to 2031-01-01T00:00:00Z

Phases
 Phase   | Outcome | Findings | Blocked by
---------+---------+----------+------------
 inspect | passed  |          |
 verify  | passed  |          |

Proof
 Suite                jws
 Algorithm            EdDSA
 Outcome              correct
 Validity             unbounded
 Deciding proof key   issuer key, from did:key
 Thumbprint           0kK-Zjs_vVav2Mgu9S8siRJe5kiAirSKcKbBklPk90c

Claims
 Path                          | Type   | Value    | Visibility
-------------------------------+--------+----------+------------
 credentialSubject.degree.name | string | (masked) | masked
 credentialSubject.degree.type | string | (masked) | masked
 credentialSubject.id          | string | (masked) | masked
 id                            | string | (masked) | masked

Findings
 Not shown   1 info finding (see --verbosity 2)

Not evaluated
 Check                | Reason
----------------------+-----------------
 issuer_accreditation | not_implemented
 context_resolution   | not_implemented

 Described in   docs/findings.md, section "Checks not evaluated"
```

A signature that has expired, in `plain`. Each line names the JSON key or path its
values come from, and the finding's detail follows its code. The error is `findings[1]`
because `findings[0]` is the `info` finding this level leaves out.

```bash
vcrd verify fixtures/exp-past.jwt --now 2026-10-01T00:00:00Z --format plain
```

```text
status: verify_failed
credential.kind: credential
credential.issuer: did:key:z6MkpsLTxWPDwHepjwD5uTTUjkg9edkaFWqSMjejg6SPTv3N
credential.types: VerifiableCredential, ExampleDegreeCredential
credential.validity: current
credential.valid_from: 2026-01-01T00:00:00Z
credential.valid_until: 2031-01-01T00:00:00Z
phases.inspect: outcome=passed
phases.verify: outcome=failed findings=verify.proof_expired
proofs[0].suite: jws
proofs[0].algorithm: EdDSA
proofs[0].outcome: correct
proofs[0].validity: expired
proofs[0].key_provenance.source: issuer_identifier
proofs[0].key_provenance.method: did:key
proofs[0].key_provenance.thumbprint: 0kK-Zjs_vVav2Mgu9S8siRJe5kiAirSKcKbBklPk90c
credential.claims.credentialSubject.degree.name: type=string value=(masked) visibility=masked
credential.claims.credentialSubject.degree.type: type=string value=(masked) visibility=masked
credential.claims.credentialSubject.id: type=string value=(masked) visibility=masked
credential.claims.id: type=string value=(masked) visibility=masked
findings[1]: code=verify.proof_expired attribution=input severity=error claim=exp now=2026-10-01T00:00:00Z skew_seconds=0 value=1780272000 value_date_time=2026-06-01T00:00:00Z
findings: 1 info finding (see --verbosity 2)
not_evaluated.issuer_accreditation: reason=not_implemented
not_evaluated.context_resolution: reason=not_implemented
```

The JSON examples below select keys with `jq`.

The curated example, inside its validity period: every phase passes. Verify's one kind of
finding is the `info` finding for `EdDSA`.

```bash
vcrd verify examples/ed25519.jwt --now 2026-10-01T00:00:00Z --format json | jq '{status, exit_code, phases}'
```

```json
{
  "status": "passed",
  "exit_code": 0,
  "phases": {
    "parse": { "outcome": "passed", "findings": [] },
    "inspect": { "outcome": "passed", "findings": [] },
    "verify": { "outcome": "passed", "findings": ["verify.algorithm_deprecated"] }
  }
}
```

A failed phase that does not block the next: `validUntil` is earlier than `validFrom`,
which also puts the clock before `validFrom`. Inspect lists both kinds of finding, and
verify still runs and finds the signature sound. `status` reports only the inspect
failure; `phases` shows both results.

```bash
vcrd verify fixtures/validity-reversed.jwt --now 2026-10-01T00:00:00Z --format json | jq '{status, exit_code, phases}'
```

```json
{
  "status": "inspect_failed",
  "exit_code": 3,
  "phases": {
    "parse": { "outcome": "passed", "findings": [] },
    "inspect": {
      "outcome": "failed",
      "findings": ["inspect.valid_until_before_valid_from", "inspect.not_yet_valid"]
    },
    "verify": { "outcome": "passed", "findings": ["verify.algorithm_deprecated"] }
  }
}
```

A credential with no `issuer`: inspect fails, and verify is blocked because there is no
key for verify to use. `blocked_by.phase` points at inspect, whose findings, here one,
say what was wrong; the top-level `findings` list has each one in full.

```bash
vcrd verify fixtures/issuer-missing.jwt --now 2026-10-01T00:00:00Z --format json | jq '{status, exit_code, phases, findings}'
```

```json
{
  "status": "inspect_failed",
  "exit_code": 3,
  "phases": {
    "parse": { "outcome": "passed", "findings": [] },
    "inspect": { "outcome": "failed", "findings": ["inspect.issuer_missing"] },
    "verify": {
      "outcome": "not_reached",
      "blocked_by": {
        "phase": "inspect",
        "reason": "impossible",
        "missing": "key_material",
        "consulted": ["issuer_identifier"]
      },
      "findings": []
    }
  },
  "findings": [
    {
      "code": "inspect.issuer_missing",
      "phase": "inspect",
      "attribution": "input",
      "severity": "error",
      "detail": { "type": "issuer_missing" }
    }
  ]
}
```

A signature that has expired while the credential has not: the JWT's `exp` is earlier than
the clock, and `validUntil` is later. Inspect passes and the signature verifies; the
proof's `validity` is `expired`, and verify fails.

```bash
vcrd verify fixtures/exp-past.jwt --now 2026-10-01T00:00:00Z --format json | jq '{status, exit_code, credential: .credential.validity, proofs: [.proofs[] | {outcome, validity}], findings: [.findings[] | {code, detail}]}'
```

```json
{
  "status": "verify_failed",
  "exit_code": 4,
  "credential": "current",
  "proofs": [{ "outcome": "correct", "validity": "expired" }],
  "findings": [
    {
      "code": "verify.algorithm_deprecated",
      "detail": { "declared": "EdDSA", "replacement": "Ed25519", "type": "algorithm_deprecated" }
    },
    {
      "code": "verify.proof_expired",
      "detail": {
        "claim": "exp",
        "now": "2026-10-01T00:00:00Z",
        "skew_seconds": 0,
        "type": "proof_expired",
        "value": 1780272000,
        "value_date_time": "2026-06-01T00:00:00Z"
      }
    }
  ]
}
```

`value` is `exp` as written, in seconds since 1970-01-01T00:00:00Z; `value_date_time` is
the same instant, `null` if it is outside the years -9999 to 9999.

A credential with no `issuer` that carries its signer's key in the header's `jwk`. With no
issuer key, vcrd refuses the embedded key, so no key decides: `outcome` is
`not_attempted`, and verify fails, attributed to the caller's policy. `proof: correct`
says the signature holds for the refused key: the credential was signed by whoever holds
that key, which is all a key the credential asserts about itself can show. There is no
`same_as_issuer_key`, since there is no issuer key to compare it with. With no deciding
proof key, the `info` finding for `EdDSA` has `replacement: null`.

```bash
vcrd verify fixtures/embedded-jwk-only.jwt --now 2026-10-01T00:00:00Z --format json | jq '{status, exit_code, proofs: [.proofs[] | {outcome, key_provenance}], findings: [.findings[] | {code, attribution}]}'
```

```json
{
  "status": "inspect_failed",
  "exit_code": 5,
  "proofs": [
    {
      "outcome": "not_attempted",
      "key_provenance": {
        "embedded_key": {
          "location": "header.jwk",
          "thumbprint": "0kK-Zjs_vVav2Mgu9S8siRJe5kiAirSKcKbBklPk90c",
          "jwk": { "crv": "Ed25519", "kty": "OKP", "x": "mr_OeAx1DyiX4A43ybyqSq5M1eqR4HqXxtw69t3R2c0" },
          "proof": "correct"
        }
      }
    }
  ],
  "findings": [
    { "code": "inspect.issuer_missing", "attribution": "input" },
    { "code": "verify.embedded_key_refused", "attribution": "policy" },
    { "code": "verify.algorithm_deprecated", "attribution": "input" }
  ]
}
```

An input that does not parse: both later phases are blocked by parse.
The header, `not`, and the payload, `a`, each fail to decode; the signature, `jws`,
decodes. Parse lists that kind of finding once, and the top-level `findings` list has one
entry for each segment, with its problem. In `not`, the `t` leaves non-zero bits after
the last whole byte; `a` is too short to encode a byte.

```bash
printf 'not.a.jws' | vcrd verify --format json | jq '{phases, findings: [.findings[] | {code, segment: .detail.segment, problem: .detail.problem}]}'
```

```json
{
  "phases": {
    "parse": { "outcome": "failed", "findings": ["parse.base64url_invalid"] },
    "inspect": {
      "outcome": "not_reached",
      "blocked_by": { "phase": "parse", "reason": "impossible" },
      "findings": []
    },
    "verify": {
      "outcome": "not_reached",
      "blocked_by": { "phase": "parse", "reason": "impossible" },
      "findings": []
    }
  },
  "findings": [
    {
      "code": "parse.base64url_invalid",
      "segment": "header",
      "problem": "nonzero_trailing_bits"
    },
    {
      "code": "parse.base64url_invalid",
      "segment": "payload",
      "problem": "invalid_length"
    }
  ]
}
```

A caller error: no phase ran, so no phase has `blocked_by`. `error.code` names the kind
of error; `error.message` has the text, which vcrd also writes to standard error.

```bash
vcrd --format json --no-such-flag 2>/dev/null | jq '{status, exit_code, error: .error.code, verify: .phases.verify}'
```

```json
{
  "status": "caller_error",
  "exit_code": 1,
  "error": "usage",
  "verify": { "outcome": "not_reached", "findings": [] }
}
```

The commands run the built binary; from a checkout, `cargo run -q -p vcrd-cli --` in place
of `vcrd` does the same.

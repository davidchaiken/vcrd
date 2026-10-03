# vcrd's JSON output

Every `vcrd` invocation prints one JSON document on standard output (REQUIREMENTS §9).
This page explains the keys and values a reader needs to interpret a result. It grows
as the output does; [ARCHITECTURE.md §6](../ARCHITECTURE.md) lists every key of the
envelope.

The schema is unstable until `schema_version` is no longer `0`: keys and values may
change between releases.

## `status` and `exit_code`

| `status` | `exit_code` | Meaning |
|---|---|---|
| `passed` | 0 | every requested phase passed |
| `caller_error` | 1 | vcrd could not run as asked: an invalid flag, an unreadable file. `error` holds a code and a message, and no phase ran. |
| `parse_failed` | 2, 5 or 6 | the earliest failed phase is parse |
| `inspect_failed` | 3, 5 or 6 | the earliest failed phase is inspect |
| `verify_failed` | 4, 5 or 6 | the earliest failed phase is verify |

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
| `phase` | always | the phase whose findings prevented this one: `parse` or `inspect`. That phase's own `findings` say what was wrong. |
| `reason` | always | `impossible`: what the phase needs is not available. `dangerous`: running it could expose vcrd to an exploit, or would fetch material such as a key from an untrustworthy source. No input produces `dangerous` yet. |
| `missing` | when `reason` is `impossible` | what the phase lacks: `document` or `key_material` |
| `consulted` | when `missing` is `key_material` | the key sources vcrd considered, none of them usable; values below |

| `missing` | Meaning |
|---|---|
| `document` | Parsing failed, so there is nothing to inspect or verify. |
| `key_material` | No key can be found to check the signature with. The credential names no usable issuer identifier (no `issuer`, or one that is not a URL, or an encoding vcrd does not read), and no other source of keys is available. |

| `consulted` value | The source |
|---|---|
| `issuer_identifier` | a key derived from the issuer identifier the credential names, such as a `did:key` |
| `caller_supplied` | keys the caller passes in (not available yet) |
| `credential_embedded` | a key the credential carries about itself, which vcrd uses only if the caller opts in (not available yet) |

The list may gain values; a consumer should accept values it does not recognize.

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

## Examples

The curated example, inside its validity period: every phase passes.

```bash
vcrd verify examples/ed25519.jwt --now 2026-10-01T00:00:00Z | jq '{status, exit_code, phases}'
```

```json
{
  "status": "passed",
  "exit_code": 0,
  "phases": {
    "parse": { "outcome": "passed", "findings": [] },
    "inspect": { "outcome": "passed", "findings": [] },
    "verify": { "outcome": "passed", "findings": [] }
  }
}
```

A failed phase that does not block the next: `validUntil` is earlier than `validFrom`,
which also puts the clock before `validFrom`. Inspect lists both kinds of finding, and
verify still runs and finds the signature sound. `status` reports only the inspect
failure; `phases` shows both results.

```bash
vcrd verify fixtures/validity-reversed.jwt --now 2026-10-01T00:00:00Z | jq '{status, exit_code, phases}'
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
    "verify": { "outcome": "passed", "findings": [] }
  }
}
```

A credential with no `issuer`: inspect fails, and verify is blocked because there is no
key to verify with. `blocked_by.phase` points at inspect, whose findings, here one,
say what was wrong; the top-level `findings` list has each one in full.

```bash
vcrd verify fixtures/issuer-missing.jwt --now 2026-10-01T00:00:00Z | jq '{status, exit_code, phases, findings}'
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

An input that does not parse: both later phases are blocked for want of a document.
The header, `not`, and the payload, `a`, each fail to decode; the signature, `jws`,
decodes. Parse lists that kind of finding once, and the top-level `findings` list has one
entry for each segment, with its problem. In `not`, the `t` leaves non-zero bits after
the last whole byte; `a` is too short to encode a byte.

```bash
printf 'not.a.jws' | vcrd verify | jq '{phases, findings: [.findings[] | {code, segment: .detail.segment, problem: .detail.problem}]}'
```

```json
{
  "phases": {
    "parse": { "outcome": "failed", "findings": ["parse.base64url_invalid"] },
    "inspect": {
      "outcome": "not_reached",
      "blocked_by": { "phase": "parse", "reason": "impossible", "missing": "document" },
      "findings": []
    },
    "verify": {
      "outcome": "not_reached",
      "blocked_by": { "phase": "parse", "reason": "impossible", "missing": "document" },
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
vcrd --no-such-flag 2>/dev/null | jq '{status, exit_code, error: .error.code, verify: .phases.verify}'
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

# Debugging vcrd

How to step through vcrd in a debugger, with a configuration known to work, and how to
check its work without one. REQUIREMENTS §6 asks for such a configuration, and counts a
procedure as documented only once it has been run end to end. This guide covers macOS,
with Visual Studio Code (VS Code) and the CodeLLDB extension. Linux is ARCHITECTURE §10
[G2], in milestone 2 of DEVELOPMENT-PLAN.md.

## Known to work

| Component | Version | Shown by |
|---|---|---|
| macOS | 27.0.1, arm64 | `sw_vers` and `uname -m` |
| VS Code | | Code > About Visual Studio Code |
| CodeLLDB | 1.12.3 | the Extensions view |
| CodeLLDB's lldb | 22.1.8 | `version` in the Debug Console: `lldb version 22.1.8-codelldb` |
| Rust | 1.99.1, the toolchain `rust-toolchain.toml` pins | `rustc --version` in the repository |

Last run end-to-end on 2026-11-11; `docs/reviews/milestone-1.md` records the commit used for this run.

## Setup

1. Install the CodeLLDB extension (`vadimcn.vscode-lldb`). Rust ships data formatters
   for lldb, which display its types, but no lldb to run them:

   ```bash
   ls "$(rustc --print sysroot)/lib/rustlib/etc"
   ```

   lists `lldb_lookup.py` and `lldb_providers.py`. CodeLLDB brings its own lldb, which
   loads them.
2. Open the repository's root folder. VS Code reads `.vscode/launch.json` from the
   folder it opened.
3. Build nothing by hand, and debug no `--release` build. The `dev` profile's defaults,
   which `Cargo.toml` leaves unchanged, keep full debugging information.

## The launch configurations

`.vscode/launch.json` holds two, in the Run and Debug view:

- **vcrd: pick an input** asks for a subcommand, `verify` or `inspect`, and an input
  from `examples/` or `fixtures/`; type to filter the list. It passes
  `--now 2026-10-01T00:00:00Z`, the clock the tests use (`NOW` in
  `vcrd-cli/tests/support/mod.rs`), so that an input gives the result its tests expect.
  The set of inputs should be correct, because the test `vcrd-cli/tests/debugging.rs`
  fails when a file in either directory is missing from the list.
- **vcrd: file in editor (current time)** runs the subcommand on the file in the active
  editor tab, with the system clock. Use it for a credential from outside the
  repository.

Both build `vcrd` before each session, through their `cargo` member, so that a session
never debugs a stale binary. Both set `"sourceLanguages": ["rust"]`, which has CodeLLDB
load Rust's formatters. If you write your own configuration, it's best to keep
both of these settings.

## A first session

1. Open `vcrd-cli/src/exit.rs`, and set a breakpoint on the first line of `exit_code`:
   `let mut vcrd = false;`.
2. Start **vcrd: pick an input**, and choose `verify` and `examples/ed25519.jwt`.
3. In the Debug Console, find the line that begins `Loading Rust formatters from`. Its
   path should begin with what `rustc --print sysroot` prints in the repository: the
   pinned toolchain. Without that line the formatters did not load, and Rust values do
   not display as their types. The console also prints:

   ```
   warning: This version of LLDB has no plugin for the language "rust". Inspection of frame variables will be limited.
   ```

   That is expected. lldb has no language plugin for Rust, which is also why it cannot
   evaluate Rust expressions ([What the debugger shows](#what-the-debugger-shows)); the
   formatters are what display Rust values.
4. When the session breaks, print the report one phase at a time. The Debug Console reads
   lldb commands; its first line is `Console is in 'commands' mode, prefix expressions
   with '?'.`

   ```
   print report->parse
   print report->inspect
   print report->verify
   print report->contained
   ```

   `parse`, `inspect` and `verify` each print `Passed`, with their `output` and
   `findings` below, and `contained` prints `size=0`. `verify` has one finding:

   ```
   (vcrd_core::report::PhaseOutcome<vcrd_core::report::VerifyOutput>) Passed{output:{proofs:size=1}, findings:size=1} {
     output = {proofs:size=1}
     findings = size=1 {
       [0] = {code:"verify.algorithm_deprecated", phase:Verify, attribution:Input, severity:Info, detail:AlgorithmDeprecated{declared:"EdDSA", replacement:Some("Ed25519")}}
     }
   }
   ```

   The same input's phases, from the command line, agree:

   ```bash
   cargo run -q -p vcrd-cli -- verify examples/ed25519.jwt --now 2026-10-01T00:00:00Z --format json | jq -c .phases
   ```

   ```
   {"parse":{"outcome":"passed","findings":[]},"inspect":{"outcome":"passed","findings":[]},"verify":{"outcome":"passed","findings":["verify.algorithm_deprecated"]}}
   ```

5. Continue. The session ends with exit code 0.

## Where to break

The tables below follow the phases in the order vcrd runs them. The result says which to
start from: its `status` (`parse_failed`, `inspect_failed` or `verify_failed`), its exit
code (2, 3 or 4), or the prefix of a finding's code (`parse.`, `inspect.` or `verify.`).

Each row names an input that reaches the function, to run with **vcrd: pick an input**
and `verify`, and what to look at there, in the Variables view or with `print`:

- **At the breakpoint**, the function's parameters are in view.
- **Step Over** (F10) runs the function a line at a time, and its locals appear as each
  is assigned.
- **Step Out** (Shift+F11) finishes the function and breaks in its caller. The value it
  returned and the caller's locals are then in view.

`vcrd-cli/tests/debugging.rs` fails when a function in these tables is not in its file.

### The run as a whole

| To see | Input | Break in | Look at | File |
|---|---|---|---|---|
| The clock skew, limits and masking in use | `examples/ed25519.jwt` | `verify` | At the breakpoint: `*ctx` | `vcrd-core/src/lib.rs` |
| The phases, in order, and that a failed inspect does not stop verify (REQUIREMENTS §4) | `fixtures/validity-reversed.jwt` | `run` | Step Over: `parse`, then `inspect` and `verify` | `vcrd-core/src/runner.rs` |
| Why verify was not reached: with no key material, verify is impossible | `fixtures/issuer-missing.jwt` | `blocked_by_inspect` | Step Out: the value returned | `vcrd-core/src/runner.rs` |
| The exit code and `status` | `examples/ed25519.jwt` | `exit_code` | At the breakpoint: `*report`, as in [A first session](#a-first-session). Step Out: the value returned | `vcrd-cli/src/exit.rs` |

### Parse and inspect

| To see | Input | Break in | Look at | File |
|---|---|---|---|---|
| The header and payload, parsed | `examples/ed25519.jwt` | `parse_compact` | Step Out: the value returned | `vcrd-core/src/formats/vc_jose.rs` |
| A segment's depth, checked against the limit before its JSON is parsed (REQUIREMENTS §6) | `fixtures/deep-nesting.jwt` | `decode_object` | Continue until it breaks a second time, with `which` set to `Payload`. Step Over: `found`, beside `limits->max_depth` | `vcrd-core/src/formats/vc_jose.rs` |
| Whether each value is a claim or metadata, and the value itself, which every output masks | `fixtures/canary.jwt` | `flatten` | Each time it breaks: `*leaves`, which gains a `Leaf`, with its `path`, `class` and `value`, for each value flattened | `vcrd-core/src/formats/vc_jose.rs` |
| Inspect's findings | `fixtures/validity-reversed.jwt` | `inspect_payload` | Step Out: `findings` and `output`, in `inspect` | `vcrd-core/src/formats/vc_jose.rs` |

### Keys

| To see | Input | Break in | Look at | File |
|---|---|---|---|---|
| The `did:key` decoded | `examples/ed25519.jwt` | `decode_did_key` | At the breakpoint: `identifier`. Step Out: the value returned | `vcrd-core/src/keys.rs` |
| Which key decides, and where it came from | `fixtures/embedded-jwk.jwt` | `resolve` | At the breakpoint: `*hints`. Step Over to its last line: `resolution` | `vcrd-core/src/keys.rs` |
| The embedded key compared with the issuer key | `fixtures/embedded-jwk.jwt` | `compare_embedded` | Step Out, into `resolve`: `resolution.provenance.thumbprint`, beside `embedded->jwk.thumbprint` | `vcrd-core/src/keys.rs` |

### Proofs

| To see | Input | Break in | Look at | File |
|---|---|---|---|---|
| The signature check, where `verify_strict` rejects the signature | `fixtures/tampered-claim.jwt` | `eddsa` | Step Out: the value returned | `vcrd-core/src/suites/jws.rs` |
| The small-order check, before `verify_strict`, which would reject the signature without naming why | `fixtures/small-order-r.jwt` | `eddsa` | Step Over: `small_order` | `vcrd-core/src/suites/jws.rs` |
| The embedded key's proof, correct where the issuer key's is incorrect (ARCHITECTURE §8, "Keys and proofs") | `fixtures/embedded-jwk.jwt` | `embedded_proof` | Step Over past `embedded.proof = …`: `embedded->proof` | `vcrd-core/src/runner.rs` |

### Setting breakpoints

A breakpoint set by function name, in the Breakpoints view, needs the crate's name:
`vcrd_core::runner::run` in the library, and `vcrd::exit::exit_code` in the command,
whose crate is named `vcrd` after its binary (`vcrd-cli/Cargo.toml`), not `vcrd_cli`.

A breakpoint on a line without code can move to the same line of another file with the
same name. One on a blank line of `vcrd-core/src/lib.rs` moved to line 60 of
`utf8parse`'s `src/lib.rs`, a dependency of `clap`, and the Debug Console said so as
the session started:

```
Breakpoint at …/vcrd/vcrd-core/src/lib.rs:60 could not be resolved, but a valid location was found at …/utf8parse-0.2.2/src/lib.rs:60
```

Read the console's first lines when a session starts, and remove a breakpoint that has
moved.

## What the debugger shows

- **Every claim value, in cleartext.** Masking (REQUIREMENTS §8; ARCHITECTURE §7)
  applies when vcrd renders a value: a `ClaimValue`'s `Debug` prints only its type,
  such as `<string>`. A debugger reads memory, so the Variables view and
  `frame variable` show the values themselves. Check debugger output before you paste
  it into an issue, a log or a transcript.
- **JSON as its members.** vcrd holds JSON as `Json`, which keeps every member of an
  object, in order, as typed data (`vcrd-core/src/json.rs`), so objects display. It
  holds no `serde_json::Value`, whose objects a debugger cannot display (ARCHITECTURE
  §3, "Typed data, not raw JSON values").
- **Fields, not methods.** lldb has no parser for Rust expressions, so an expression
  that calls a method fails. Read the fields instead; `->` follows a reference, as in
  `print report->verify`.
- **One field at a time.** A value's summary includes the summaries of everything it
  holds, so printing a whole `Report`, even with `frame variable -D 1 *report`, gives
  one very long line. Print one field, as in step 4 of
  [A first session](#a-first-session).
- **Times as written, beside their values.** A `Timestamp` keeps the text it was read
  from, `lexical`, beside the parsed `time::OffsetDateTime`, whose fields are that
  crate's internal representation, such as `date:{value:2074625}`. Read `lexical`.

## Debugging tests

- **vcrd-core's tests**, its unit tests and those in `vcrd-core/tests/`: use
  rust-analyzer's Debug link above each test. It does not read `.vscode/launch.json`;
  it builds the test and starts CodeLLDB itself. Check its Debug Console as in step 3
  of [A first session](#a-first-session): the Debug link can load the formatters of
  rustup's default toolchain rather than the pinned one's.
- **vcrd-cli's tests**, in `vcrd-cli/tests/`, run `vcrd` as a child process
  (`support::vcrd()`, through `assert_cmd`), so a breakpoint in `vcrd` is never reached
  from a test. Run the test's command line with **vcrd: pick an input**, which uses the
  tests' clock.

## Without a debugger

`--format json` reports everything vcrd established about an input, and
[docs/output.md](output.md) explains how to read it. The scripts in
`scripts/debugging/` check some of it with other tools: `base64`, `jq`, `bc`, `xxd` and
`openssl`, whichever are first on your `PATH`. They were run with macOS's `base64`,
`jq` 1.7.1, `bc` 7.0.3 and `xxd`, and with both OpenSSL 3.6.3 and LibreSSL 3.3.6.

### The JWS, decoded

**This bypasses vcrd's masking: every claim value prints in cleartext.**

```bash
scripts/debugging/jws-decode.sh examples/ed25519.jwt
```

prints the header, then the payload, each as JSON. The header:

```json
{
  "alg": "EdDSA",
  "cty": "vc",
  "kid": "did:key:z6MkpsLTxWPDwHepjwD5uTTUjkg9edkaFWqSMjejg6SPTv3N#z6MkpsLTxWPDwHepjwD5uTTUjkg9edkaFWqSMjejg6SPTv3N",
  "typ": "vc+jwt"
}
```

### A key's JWK and thumbprint

The issuer's `did:key`, as a JWK, and its thumbprint:

```bash
scripts/debugging/did-key-jwk.sh did:key:z6MkpsLTxWPDwHepjwD5uTTUjkg9edkaFWqSMjejg6SPTv3N
scripts/debugging/did-key-jwk.sh did:key:z6MkpsLTxWPDwHepjwD5uTTUjkg9edkaFWqSMjejg6SPTv3N | scripts/debugging/jwk-thumbprint.sh
```

```
{"crv":"Ed25519","kty":"OKP","x":"mr_OeAx1DyiX4A43ybyqSq5M1eqR4HqXxtw69t3R2c0"}
0kK-Zjs_vVav2Mgu9S8siRJe5kiAirSKcKbBklPk90c
```

These are the `jwk` and `thumbprint` that `--format json` reports in
`proofs[0].key_provenance`. `jwk-thumbprint.sh` reads any OKP JWK, such as an embedded
key from vcrd's own output:

```bash
cargo run -q -p vcrd-cli -- verify fixtures/embedded-jwk.jwt --now 2026-10-01T00:00:00Z --format json | jq '.proofs[0].key_provenance.embedded_key.jwk' | scripts/debugging/jwk-thumbprint.sh
```

```
_i3gzFWABuHlZnuT9FBtp8CVlJ57CcWpTPwviZ2m1ms
```

### The scripts

Quoted in full; `vcrd-cli/tests/debugging.rs` fails when a quotation differs from its
script.

`scripts/debugging/b64url-decode.sh`:

```bash
#!/usr/bin/env bash
# Decodes base64url (RFC 4648 §5) from standard input, restoring the padding it
# omits. Needs bash (3.2 or later) and base64.
set -euo pipefail
s=$(tr -d '\n' | tr '_-' '/+')
while (( ${#s} % 4 )); do s+="="; done
printf '%s' "$s" | base64 -d
```

`scripts/debugging/b64url-encode.sh`:

```bash
#!/usr/bin/env bash
# Encodes standard input as base64url (RFC 4648 §5), without padding or a final
# newline. Needs bash (3.2 or later) and base64.
set -euo pipefail
base64 | tr '+/' '-_' | tr -d '=\n'
```

`scripts/debugging/jws-decode.sh`:

```bash
#!/usr/bin/env bash
# Prints the header and then the payload of a compact JWS (RFC 7515 §7.1), each as
# JSON. This bypasses vcrd's masking: every claim value prints in cleartext.
# Needs bash (3.2 or later), base64 and jq.
set -euo pipefail
here=$(dirname "$0")
jws=${1:?usage: jws-decode.sh FILE}
echo "jws-decode.sh: claim values are not masked" >&2
for n in 1 2; do
  cut -d. -f"$n" "$jws" | "$here/b64url-decode.sh" | jq .
done
```

`scripts/debugging/did-key-jwk.sh`:

```bash
#!/usr/bin/env bash
# Prints the JWK (RFC 8037 §2) of an Ed25519 did:key (did:key v0.9), in the form
# RFC 7638 hashes for a thumbprint. Needs bash (3.2 or later), bc, xxd and base64.
set -euo pipefail
here=$(dirname "$0")
did=${1:?usage: did-key-jwk.sh DID}
alphabet=123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
# z: the multibase prefix for base58btc.
b58=${did#did:key:z}
if [[ $b58 == "$did" || -z $b58 || $b58 == *[!$alphabet]* ]]; then
  echo "did-key-jwk.sh: not a base58btc did:key: $did" >&2
  exit 1
fi
# Each character's position in the alphabet is one base-58 digit. bc prints the
# number in hexadecimal, and wraps long lines with a backslash.
hex=$( { echo 'obase=16; n=0'
         for (( i = 0; i < ${#b58}; i++ )); do
           p=${alphabet%%"${b58:i:1}"*}
           echo "n=n*58+${#p}"
         done
         echo n; } | bc | tr -d '\\\n' )
# The multicodec prefix 0xed, ed25519-pub, as an unsigned varint; then the 32-byte
# key. The prefix leaves no leading zero for bc to drop.
if [[ $hex != ED01* || ${#hex} -ne 68 ]]; then
  echo "did-key-jwk.sh: not an Ed25519 did:key: $did" >&2
  exit 1
fi
x=$(printf '%s' "${hex#ED01}" | xxd -r -p | "$here/b64url-encode.sh")
printf '{"crv":"Ed25519","kty":"OKP","x":"%s"}\n' "$x"
```

`scripts/debugging/jwk-thumbprint.sh`:

```bash
#!/usr/bin/env bash
# Prints the RFC 7638 thumbprint of a JWK read from standard input: SHA-256 over
# its required members (RFC 8037 §2 for an OKP key), in lexicographic order and
# with no whitespace, encoded as base64url. OKP keys only, so far. Needs bash (3.2
# or later), jq, openssl and base64.
set -euo pipefail
here=$(dirname "$0")
jwk=$(jq -cjS 'if .kty == "OKP" then {crv, kty, x} else error("OKP keys only") end')
printf '%s' "$jwk" | openssl dgst -sha256 -binary | "$here/b64url-encode.sh"
echo
```

## A caution, especially for LLM-based agents

A debugger is a complicated tool with very specific configuration requirements.
Speaking from an AI agent's experience with an improperly configured debugger...
Before you trust what the debugger shows, check values against an independent environment,
such as `vcrd <command> --format json` for the same input.

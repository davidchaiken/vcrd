# Debugging the spike

**Use CodeLLDB, not `rust-lldb`.** On macOS the two are not interchangeable: one works
and the other hangs. See [The toolchain dependency](#the-toolchain-dependency) for why.

The dev profile is already set up in `Cargo.toml`: `debug = 2`, `opt-level = 0`,
`split-debuginfo = "unpacked"`. Nothing here ever needs `--release`.

## Setup

Install the [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb)
extension (`vadimcn.vscode-lldb`), then make sure every launch configuration carries:

```json
"sourceLanguages": ["rust"]
```

Without it the Rust formatters never load and enums print as raw `$variants$` blocks
with all arms shown at once. With it, the Debug Console prints
`Loading Rust formatters from <sysroot>/lib/rustlib/etc` at session start — that line is
the confirmation that it worked.

`.vscode/launch.json` in this directory has five ready configurations, each already
carrying `sourceLanguages` and a `cargo` build step so the binary is never stale. Note
that VS Code reads the `.vscode/launch.json` of the folder you opened; if your workspace
root is the repository rather than `prototype/`, use that copy and set `cwd` to
`${workspaceRoot}/prototype`.

## Start here

Run **verify expired.jwt (graduated result)**, break on `vcrd::exit_code::from_report`,
and print the whole report one level deep:

```
frame variable -D 1 *report
```

```
parse    = Passed{output:{...}, findings:size=0}
validate = Failed{findings:size=1}
verify   = Passed{output:{proofs:size=1}, findings:size=0}
```

Those three lines *are* the answer to question 1: a correctly signed but expired
credential, with validate and verify reporting independently.

## Breakpoint anchors

Each is `#[inline(never)]` so it survives as a real symbol. One per design question.

| Question | Anchor |
|---|---|
| 1 — result shape | `vcrd_core::pipeline::run_parse` / `run_validate` / `run_verify` |
| 2 — view model | `vcrd::view::from_report` |
| 3 — redaction | `vcrd_core::redact::classify` |
| 4 — format/suite seam | `vcrd_core::jwt_vc::JwtVcFormat::parse` |
| 5 — algorithm policy | `vcrd_core::jws::select_algorithm` |
| 6 — key provenance | `vcrd_core::keys::resolve` |
| 7 — temporal semantics | `vcrd_core::validate::check_temporal` |
| exit codes | `vcrd::exit_code::from_report` |

## <a id="the-toolchain-dependency"></a>The toolchain dependency

Rust does not ship an lldb binary — no rustup component provides one. It ships *data
formatters*, as Python, in `$(rustc --print=sysroot)/lib/rustlib/etc/`. Which lldb
executes that Python is therefore the whole question.

| Configuration | Result |
|---|---|
| CodeLLDB 1.12.3 + `sourceLanguages: ["rust"]` | works |
| CodeLLDB without `sourceLanguages` | no formatters load; raw `$variants$` output |
| `rust-lldb` over Apple `/usr/bin/lldb` (2100.0.17.203) | **hangs the session** |
| Homebrew LLVM | not an alternative — same formatters, unsigned `debugserver` |

`rust-lldb` prefers `$sysroot/lib/rustlib/$host/bin/lldb`, which does not exist, so it
falls back to `/usr/bin/lldb`. There, `StdStringSummaryProvider`
(`lldb_providers.py:317`) computes a bad address for any `String` reached through
nesting, raises `ReadMemory error`, and wedges the debugger. `frame variable -D 1
*report` hangs on `report->parse`; `report->validate` and `report->verify` are fine
because their payloads contain no `String`.

Both debuggers print `warning: This version of LLDB has no plugin for the language
"rust"`. That warning is normal and does not distinguish the working configuration from
the broken one.

If you are stuck with Apple's toolchain, disable the formatters and read discriminants
directly. This never hangs, and it is immune to formatter bugs:

```
b vcrd::exit_code::from_report
run
type category disable Rust
expr -- (unsigned char)*(unsigned char*)&report->verify
```

The tag is the variant's declaration index in `model.rs` — `0 = NotReached`,
`1 = Failed`, `2 = Passed`.

## Other things that will waste your time

**1. CLI symbols use the *binary* name, not the crate name.** The crate is `vcrd-cli`
but `[[bin]] name = "vcrd"`, so the symbol path is `vcrd::exit_code::from_report`, not
`vcrd_cli::...`. Core symbols do use `vcrd_core::`. When a breakpoint silently never
fires, this is usually why:

```
image lookup -r -n from_report
```

**2. Print with a depth limit.** A whole `Report` is thousands of lines; use
`frame variable -D 1`. If you exceed the default child depth, lldb tells you to raise
`target.max-children-depth`.

**3. lldb cannot call Rust methods.** `expression -- x.is_some()` falls back to
Objective-C++ and errors. Read fields, not methods:

```
p hints->embedded_jwk            # works
p hints.embedded_jwk.is_some()   # does not
```

**4. `serde_json::Value::Object` is opaque in the debugger.** Rust's formatters have no
summary provider for `serde_json::Map`, so an object shows only its backing store's
internals — no keys, no values, at any depth. This is true both ways:

```
preserve_order on   Object({map:{core:{indices:{raw:{table:{bucket_mask:3, ctrl:...
preserve_order off  Object({map:{root:Some({height:0, node:{pointer:0x...}}), length:3, ...
```

Do not spend time trying to read one. Scalars are fine — `flatten_claims` reduces claims
to leaves, so `ClaimValue` always holds a string, number, or bool and prints correctly.
The only `Value::Object` reachable from a `Report` is `KeyHints.embedded_jwk`
(`keys.rs:53`); to see its contents, print the JWK from program output instead.

The workspace leaves `preserve_order` off for wire-contract reasons, not debugging ones
— alphabetical key order is stable under refactoring, insertion order is not. To confirm
a change to that feature actually rebuilt, without starting a debugger (`type` first
means on, `detected` first means off):

```bash
./target/debug/vcrd verify fixtures/vcdm11-mapping.jwt --now 2026-08-22T12:00:00Z --format json | python3 -c "import json,sys; print(list(json.load(sys.stdin)['findings'][0]['detail'].keys())[0])"
```

**5. Rebuild before you conclude anything.** A launch configuration without a `cargo`
build step debugs whatever binary is on disk. The bundled configurations all build
first; a hand-written one may not.

**6. The redaction newtype does not protect against a debugger.** `ClaimValue`'s
guarantee covers `Display`, `Debug`, and `Serialize`; a memory inspector reads straight
past it — `credentialSubject.id` appears in cleartext in the frame view. That is
acceptable, since a debugger is trusted, but do not over-claim the newtype's reach.

## Debugging the tests

`assert_cmd` spawns the binary as a subprocess, so breakpoints do not hit through
`cargo test`. Every test case is a plain invocation; debug the invocation instead. For
`vcrd-core` unit tests, use the **vcrd-core unit tests** launch configuration.

## Fixtures worth walking

| Fixture | Why |
|---|---|
| `expired.jwt` | validate fails while verify passes — graduated success, visible in one frame |
| `embedded-jwk.jwt` | stop in `keys::resolve` and watch the independent `did:key` win over the header key |
| `alg-confusion-hs256.jwt` | stop in `jws::select_algorithm` (HS256 is accepted), then in `verify_signature` where the key-type check rejects it |
| `deep-nesting.jwt` | `limits::measure_depth` bailing before any JSON is built |

## A caution

A debugger is an instrument. This spike recorded a finding — that a `#[repr(u8)]`
attribute was needed for lldb to read an enum discriminant — that turned out to be an
artifact of the broken `rust-lldb` path, and was retracted once the debugger worked.
Validate the tooling before trusting what it shows you.

# Test inputs

vcrd's tests use four kinds of input (REQUIREMENTS §11):

| Kind | Where | What it is |
|---|---|---|
| Curated examples | [`examples/`](../examples) | One canonical, self-signed, known-good credential per supported proof format. The README points at them, and they are the tests' positive inputs. |
| Negative fixtures | this directory | Inputs that each exercise one condition. A test asserts the finding code, attribution and exit code vcrd gives for each. |
| Generated inputs | inside the tests | Inputs too large or too trivial to be worth a file, such as the one over the size limit. |
| Vendored conformance fixtures | not yet present | Copies of third-party test suites (W3C VC Test Suite, DID Test Suite, RDFC-1.0 vectors). They will be kept apart from these, with each source's repository, commit and licence recorded. |

An input is committed here when it is small and useful beyond its test, for example to
run by hand or to step through in a debugger. Otherwise its test generates it.

## How they are made

Every file here and in `examples/` is generated deterministically, from fixed seeds, by
the test-only helper in
[`vcrd-core/tests/fixtures.rs`](../vcrd-core/tests/fixtures.rs); the helper never ships.
A test fails when a committed file differs from what the helper produces, and another
test fails when a fixture is missing from the table below. To regenerate after changing
the helper:

```bash
cargo test -p vcrd-core --test fixtures -- --ignored regenerate
```

Every value in them is invented; none is anyone's personal data.

## Fixtures

Exit codes are ARCHITECTURE §6's. Each fixture is derived from the curated example unless
it says otherwise.

| File | Condition | Finding | Attribution | Exit |
|---|---|---|---|---|
| `deep-nesting.jwt` | The payload nests 42 levels deep, over the default depth limit of 32 and under `serde_json`'s own 128. | `parse.nesting_too_deep` | policy | 5 |
| `jws-json-flattened.json` | The example in flattened JWS JSON serialization (RFC 7515 §7.2.2), which vcrd recognizes but does not read yet (ARCHITECTURE §10 [F1]). | `parse.jws_json_serialization` | vcrd | 6 |
| `validity-reversed.jwt` | `validUntil` (2026-01-01) is earlier than `validFrom` (2031-01-01), which VCDM 2.0 §4.9 forbids. Correctly signed, so verify passes. Against a clock, a second finding says the credential is not yet valid or has expired. | `inspect.valid_until_before_valid_from` | input | 3 |
| `issuer-missing.jwt` | No `issuer` (VCDM 2.0 §4.7). With no issuer identifier there is no key, so verify is blocked: `blocked_by` names `key_material` as missing. | `inspect.issuer_missing` | input | 3 |
| `iss-mismatch.jwt` | `iss` is `did:example:someone-else`, not the issuer, which VC-JOSE-COSE §4.1.2 forbids. Signed by the issuer's key, so verify passes. | `inspect.iss_mismatch` | input | 3 |
| `kid-missing.jwt` | No `kid`, which VC-JOSE-COSE §4.1.1 requires when the issuer is a DID. Verify still passes: `kid` never chooses the key. | `inspect.kid_missing` | input | 3 |
| `vcdm-1.1-encoding.jwt` | The example's credential in VCDM 1.1's JWT encoding, inside a `vc` claim, which vcrd does not read yet (ARCHITECTURE §10 [F2]). Verify is blocked, since the issuer is in `iss`. | `inspect.vcdm_1_1_jwt_encoding` | vcrd | 6 |

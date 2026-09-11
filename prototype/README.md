# vcrd prototype — THROWAWAY

This is a spike, not a foundation. It exists to answer the seven design questions in
[`../prototype-goals.md`](../prototype-goals.md), and the answers live in
[`../PROTOTYPE-FINDINGS.md`](../PROTOTYPE-FINDINGS.md). **Read the findings; this code
is disposable.** It is a self-contained Cargo workspace deliberately not wired into any
future root workspace, and it is not intended to be merged.

Scope: VC-JOSE-COSE (VCDM 2.0) over compact JWS. Five algorithms (EdDSA, ES256, ES512,
RS256, HS256). `did:key` and caller-supplied JWK sets. No network, no JSON-LD, no
selective disclosure.

```bash
cargo test --workspace
cargo run -p vcrd-cli -- verify fixtures/expired.jwt --now 2026-08-22T12:00:00Z
cargo run -p vcrd-cli -- inspect fixtures/happy-ed25519.jwt --now 2026-08-22T12:00:00Z --explain-redaction
cargo run -p vcrd-cli -- measure fixtures/*.jwt
```

- `vcrd-core/` — model, traits, JWS, key resolution, redaction
- `vcrd-cli/` — the `vcrd` binary: clap, view model, `text`/`json`/`plain` renderers
- `fixtures-gen/` — dev-only, mints `fixtures/` deterministically from fixed seeds
- `fixtures/` — 14 committed fixtures, negative-first; see `fixtures/MANIFEST.json`
- [`DEBUGGING.md`](DEBUGGING.md) — breakpoint anchors and `rust-lldb` recipes

The josekit comparison probe (finding 5) needs OpenSSL:

```bash
OPENSSL_DIR=/opt/homebrew/opt/openssl@3 cargo test -p vcrd-core --features josekit-probe -- --nocapture josekit
```

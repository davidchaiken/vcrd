# vcrd
Verifiable Credentials tools

## Try it

vcrd is in early development. It reads one format so far: a VC-JOSE-COSE credential
signed with Ed25519 by a `did:key` issuer. [`examples/ed25519.jwt`](examples/ed25519.jwt)
is one, self-signed:

```bash
cargo run -p vcrd-cli -- verify examples/ed25519.jwt --now 2026-10-01T00:00:00Z
```

The result is one JSON document on standard output, with every claim value masked.

The example is valid from 2026-01-01 to 2031-01-01. The command passes `--now` so that
it gives the same answer on any date; without it, vcrd uses the system clock, and from
2031 reports the example expired though its signature still verifies.

[`fixtures/`](fixtures/README.md) holds the negative test inputs, each exercising one
condition vcrd must report.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Any contribution intentionally submitted for inclusion in vcrd by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

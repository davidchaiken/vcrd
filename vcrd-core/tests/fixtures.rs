//! The committed fixtures and curated examples, and the dev-only helper that signs
//! them (REQUIREMENTS §11). The helper is test code, so it never ships.
//!
//! Each file is generated deterministically from fixed seeds. One test fails when a
//! committed file differs from what the helper produces, and another when a fixture
//! is missing from fixtures/README.md. The third, ignored by default, rewrites them:
//!
//! ```text
//! cargo test -p vcrd-core --test fixtures -- --ignored regenerate
//! ```

use std::path::PathBuf;

/// fixtures/README.md is where a reader learns what each fixture exercises and what
/// vcrd must say about it.
#[test]
fn every_fixture_is_in_the_readme_table() {
    let readme = std::fs::read_to_string(generate::repo_root().join("fixtures/README.md"))
        .expect("fixtures/README.md");
    for (path, _) in generate::all() {
        if let Some(name) = path.strip_prefix("fixtures/") {
            assert!(
                readme.contains(&format!("| `{name}` |")),
                "{name} has no row in fixtures/README.md"
            );
        }
    }
}

#[test]
fn committed_files_match_the_generator() {
    for (path, generated) in generate::all() {
        let committed = std::fs::read(generate::repo_root().join(path))
            .unwrap_or_else(|e| panic!("{path}: {e}; run the regenerate test"));
        assert!(
            committed == generated,
            "{path} differs from the generator; run the regenerate test"
        );
    }
}

#[test]
#[ignore = "rewrites the committed fixtures"]
fn regenerate() {
    for (path, generated) in generate::all() {
        let path: PathBuf = generate::repo_root().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, generated).unwrap();
    }
}

/// In a `#[cfg(test)]` module so that the workspace's panic lints exempt it, as
/// they do test functions (docs/reviews/milestone-0.md, gap 1).
#[cfg(test)]
mod generate {
    use std::path::PathBuf;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    pub fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    /// Every generated file, by path from the repository root. The negative
    /// fixtures under fixtures/ are named for the condition each exercises; the tests
    /// that use them assert its finding code, attribution and exit code.
    pub fn all() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("examples/ed25519.jwt", ed25519_example()),
            ("fixtures/deep-nesting.jwt", deep_nesting()),
            ("fixtures/jws-json-flattened.json", jws_json_flattened()),
        ]
    }

    /// A signing key from a seed derived from a label, so that each fixture's key is
    /// fixed and distinct.
    fn signing_key(label: &str) -> SigningKey {
        SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
    }

    /// `did:key` for an Ed25519 key: base58btc of the `ed25519-pub` multicodec
    /// prefix (0xed, as an unsigned varint) and the key.
    fn did_key(key: &SigningKey) -> String {
        let bytes = [&[0xed, 0x01][..], key.verifying_key().as_bytes()].concat();
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// The encoded header and payload, and the signature over them (RFC 7515 §5.1).
    /// serde_json sorts object members, so the bytes are the same on every run.
    fn sign_parts(key: &SigningKey, header: &Value, payload: &Value) -> [String; 3] {
        let header = b64(&serde_json::to_vec(header).unwrap());
        let payload = b64(&serde_json::to_vec(payload).unwrap());
        let signature = key.sign(format!("{header}.{payload}").as_bytes());
        [header, payload, b64(&signature.to_bytes())]
    }

    /// A compact JWS (RFC 7515 §7.1).
    fn sign(key: &SigningKey, header: &Value, payload: &Value) -> Vec<u8> {
        sign_parts(key, header, payload).join(".").into_bytes()
    }

    /// The curated example: a self-signed VC-JOSE-COSE credential whose issuer is a
    /// `did:key` (DEVELOPMENT-PLAN.md, milestone 1).
    fn ed25519_example() -> Vec<u8> {
        let (key, header, payload) = example_parts();
        sign(&key, &header, &payload)
    }

    /// Over the default depth limit of 32 (ARCHITECTURE §4) and under serde_json's
    /// own 128: the example with 40 objects nested in its subject, 42 levels in all.
    fn deep_nesting() -> Vec<u8> {
        let (key, header, mut payload) = example_parts();
        let mut nested = json!("deep");
        for _ in 0..40 {
            nested = json!({ "n": nested });
        }
        payload["credentialSubject"]["nested"] = nested;
        sign(&key, &header, &payload)
    }

    /// The example as a JWS in flattened JSON serialization (RFC 7515 §7.2.2), which
    /// vcrd recognizes and does not yet read (ARCHITECTURE §10 [F1]).
    fn jws_json_flattened() -> Vec<u8> {
        let (key, header, payload) = example_parts();
        let [protected, payload, signature] = sign_parts(&key, &header, &payload);
        let jws = json!({ "payload": payload, "protected": protected, "signature": signature });
        serde_json::to_vec(&jws).unwrap()
    }

    /// The curated example's key, header and payload.
    fn example_parts() -> (SigningKey, Value, Value) {
        let key = signing_key("vcrd curated example: Ed25519 issuer");
        let issuer = did_key(&key);
        let fragment = issuer.strip_prefix("did:key:").unwrap();
        let header = json!({
            "alg": "EdDSA",
            "cty": "vc",
            "kid": format!("{issuer}#{fragment}"),
            "typ": "vc+jwt",
        });
        let payload = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2",
            ],
            "id": "urn:uuid:0d4a1f3e-6c2b-4e8a-9b1d-2f7c5a3e8b90",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": issuer,
            "validFrom": "2026-01-01T00:00:00Z",
            "validUntil": "2031-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:alice",
                "degree": {
                    "type": "ExampleBachelorDegree",
                    "name": "Bachelor of Science",
                },
            },
        });
        (key, header, payload)
    }
}

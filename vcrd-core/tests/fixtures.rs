//! The committed fixtures and curated examples, and the dev-only helper that signs
//! them (REQUIREMENTS §11). The helper is test code, so it never ships.
//!
//! Each file is generated deterministically from fixed seeds. The first test fails
//! when a committed file differs from what the helper produces. The second, ignored
//! by default, rewrites them:
//!
//! ```text
//! cargo test -p vcrd-core --test fixtures -- --ignored regenerate
//! ```

use std::path::PathBuf;

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

    /// Every generated file, by path from the repository root.
    pub fn all() -> Vec<(&'static str, Vec<u8>)> {
        vec![("examples/ed25519.jwt", ed25519_example())]
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

    /// A compact JWS (RFC 7515 §7.1). serde_json sorts object members, so the bytes
    /// are the same on every run.
    fn sign(key: &SigningKey, header: &Value, payload: &Value) -> Vec<u8> {
        let signing_input = format!(
            "{}.{}",
            b64(&serde_json::to_vec(header).unwrap()),
            b64(&serde_json::to_vec(payload).unwrap())
        );
        let signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64(&signature.to_bytes())).into_bytes()
    }

    /// The curated example: a self-signed VC-JOSE-COSE credential whose issuer is a
    /// `did:key` (DEVELOPMENT-PLAN.md, milestone 1).
    fn ed25519_example() -> Vec<u8> {
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
        sign(&key, &header, &payload)
    }
}

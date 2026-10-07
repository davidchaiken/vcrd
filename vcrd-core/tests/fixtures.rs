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

/// The weak-key and small-order fixtures carry signatures that a verifier without
/// those checks accepts, so that their tests exercise vcrd's checks rather than a
/// signature that fails for some other reason (ARCHITECTURE §8). ed25519-dalek's
/// `verify` checks [s]B = R + [k]A and nothing more; `verify_strict`, which vcrd
/// uses, also rejects a small-order R or public key.
#[test]
fn a_lax_verifier_accepts_the_weak_key_and_small_order_signatures() {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    for name in ["weak-key.jwt", "small-order-r.jwt"] {
        let (public, signing_input, signature) = generate::issuer_key_and_signature(name);
        let key = VerifyingKey::from_bytes(&public).unwrap();
        let signature = Signature::from_bytes(&signature);
        assert!(key.verify(&signing_input, &signature).is_ok(), "{name}");
        assert!(
            key.verify_strict(&signing_input, &signature).is_err(),
            "{name}"
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
    use curve25519_dalek::traits::Identity as _;
    use curve25519_dalek::{EdwardsPoint, Scalar};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256, Sha512};

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
            ("fixtures/validity-reversed.jwt", validity_reversed()),
            ("fixtures/issuer-missing.jwt", issuer_missing()),
            ("fixtures/iss-mismatch.jwt", iss_mismatch()),
            ("fixtures/kid-missing.jwt", kid_missing()),
            ("fixtures/vcdm-1.1-encoding.jwt", vcdm_1_1_encoding()),
            ("fixtures/tampered-claim.jwt", tampered_claim()),
            ("fixtures/alg-none.jwt", alg_none()),
            ("fixtures/alg-es256.jwt", alg_es256()),
            ("fixtures/weak-key.jwt", weak_key()),
            ("fixtures/small-order-r.jwt", small_order_r()),
            ("fixtures/embedded-jwk.jwt", embedded_jwk()),
            ("fixtures/embedded-jwk-only.jwt", embedded_jwk_only()),
            ("fixtures/exp-past.jwt", exp_past()),
            ("fixtures/crit-unsupported.jwt", crit_unsupported()),
        ]
    }

    /// A committed fixture's issuer key, decoded from its `did:key`, with its signing
    /// input and signature.
    pub fn issuer_key_and_signature(name: &str) -> ([u8; 32], Vec<u8>, [u8; 64]) {
        let path = repo_root().join("fixtures").join(name);
        let token = String::from_utf8(std::fs::read(path).unwrap()).unwrap();
        let (signing_input, signature) = token.rsplit_once('.').unwrap();
        let payload = signing_input.split('.').nth(1).unwrap();
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        let issuer = payload["issuer"].as_str().unwrap();
        let encoded = issuer.strip_prefix("did:key:z").unwrap();
        let decoded = bs58::decode(encoded).into_vec().unwrap();
        let public = decoded.strip_prefix(&[0xed, 0x01][..]).unwrap();
        (
            public.try_into().unwrap(),
            signing_input.as_bytes().to_vec(),
            URL_SAFE_NO_PAD
                .decode(signature)
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }

    /// A signing key from a seed derived from a label, so that each fixture's key is
    /// fixed and distinct.
    fn signing_key(label: &str) -> SigningKey {
        SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
    }

    /// `did:key` for an Ed25519 key: base58btc of the `ed25519-pub` multicodec
    /// prefix (0xed, as an unsigned varint) and the key.
    fn did_key(key: &SigningKey) -> String {
        did_key_of(key.verifying_key().as_bytes())
    }

    /// As [`did_key`], for any 32 bytes, including a point no signing key has.
    fn did_key_of(public: &[u8; 32]) -> String {
        let bytes = [&[0xed, 0x01][..], public].concat();
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    /// An Ed25519 public key as a JWK (RFC 8037 §2).
    fn jwk(key: &SigningKey) -> Value {
        json!({"kty": "OKP", "crv": "Ed25519", "x": b64(key.verifying_key().as_bytes())})
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn b64_json(value: &Value) -> String {
        b64(&serde_json::to_vec(value).unwrap())
    }

    /// The encoded header and payload, and the signature over them (RFC 7515 §5.1).
    /// serde_json sorts object members, so the bytes are the same on every run.
    fn sign_parts(key: &SigningKey, header: &Value, payload: &Value) -> [String; 3] {
        let header = b64_json(header);
        let payload = b64_json(payload);
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

    /// The example's validity bounds swapped: `validUntil` earlier than `validFrom`
    /// (VCDM 2.0 §4.9; ARCHITECTURE §10 [S3]). Correctly signed.
    fn validity_reversed() -> Vec<u8> {
        let (key, header, mut payload) = example_parts();
        payload["validFrom"] = json!("2031-01-01T00:00:00Z");
        payload["validUntil"] = json!("2026-01-01T00:00:00Z");
        sign(&key, &header, &payload)
    }

    /// The example with no `issuer` (VCDM 2.0 §4.7): there is no identifier to derive
    /// a key from, so verify is blocked. Correctly signed.
    fn issuer_missing() -> Vec<u8> {
        let (key, header, mut payload) = example_parts();
        payload.as_object_mut().unwrap().remove("issuer");
        sign(&key, &header, &payload)
    }

    /// The example with an `iss` naming someone other than the issuer (VC-JOSE-COSE
    /// §4.1.2). Correctly signed by the issuer's key.
    fn iss_mismatch() -> Vec<u8> {
        let (key, header, mut payload) = example_parts();
        payload["iss"] = json!("did:example:someone-else");
        sign(&key, &header, &payload)
    }

    /// The example without `kid`, which VC-JOSE-COSE §4.1.1 requires when the issuer
    /// is a DID. Correctly signed.
    fn kid_missing() -> Vec<u8> {
        let (key, mut header, payload) = example_parts();
        header.as_object_mut().unwrap().remove("kid");
        sign(&key, &header, &payload)
    }

    /// The example's credential in VCDM 1.1's JWT encoding: inside a `vc` claim, with
    /// the issuer, identifier, subject and validity as `iss`, `jti`, `sub`, `nbf` and
    /// `exp`. vcrd does not read it yet (ARCHITECTURE §10 [F2]). The header is the
    /// example's, so that the encoding is the one condition.
    fn vcdm_1_1_encoding() -> Vec<u8> {
        let (key, header, example) = example_parts();
        let payload = json!({
            "iss": example["issuer"],
            "jti": example["id"],
            "sub": example["credentialSubject"]["id"],
            // 2026-01-01T00:00:00Z and 2031-01-01T00:00:00Z.
            "nbf": 1767225600,
            "exp": 1924992000,
            "vc": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1",
                ],
                "type": example["type"],
                "credentialSubject": {"degree": example["credentialSubject"]["degree"]},
            },
        });
        sign(&key, &header, &payload)
    }

    /// The example with a claim changed after signing: the degree's name. The
    /// signature is the example's, over the original payload.
    fn tampered_claim() -> Vec<u8> {
        let (key, header, mut payload) = example_parts();
        let [header, _, signature] = sign_parts(&key, &header, &payload);
        payload["credentialSubject"]["degree"]["name"] = json!("Doctor of Philosophy");
        [header, b64_json(&payload), signature]
            .join(".")
            .into_bytes()
    }

    /// The example declaring `alg: none`, as an Unsecured JWS, whose signature is
    /// empty (RFC 7518 §3.6). vcrd always rejects it (ARCHITECTURE §8).
    fn alg_none() -> Vec<u8> {
        let (_, mut header, payload) = example_parts();
        header["alg"] = json!("none");
        format!("{}.{}.", b64_json(&header), b64_json(&payload)).into_bytes()
    }

    /// The example declaring `alg: ES256`, which vcrd does not implement yet, with 64
    /// zero bytes where an ES256 signature would be. vcrd rejects the algorithm by
    /// name and never reads the signature.
    fn alg_es256() -> Vec<u8> {
        let (_, mut header, payload) = example_parts();
        header["alg"] = json!("ES256");
        [b64_json(&header), b64_json(&payload), b64(&[0; 64])]
            .join(".")
            .into_bytes()
    }

    /// An issuer whose `did:key` encodes the identity point, which has small order
    /// (ARCHITECTURE §8). Under that key [s]B = R + [k]A reduces to [s]B = R, so any
    /// R = [s]B verifies for every message in a verifier that does not reject weak
    /// keys; the signature is one such pair.
    fn weak_key() -> Vec<u8> {
        let issuer = did_key_of(&EdwardsPoint::identity().compress().0);
        let (header, payload) = credential_parts(&issuer);
        let s = Scalar::from_bytes_mod_order(Sha256::digest(b"vcrd fixture: weak-key s").into());
        let signature = [EdwardsPoint::mul_base(&s).compress().0, s.to_bytes()].concat();
        [b64_json(&header), b64_json(&payload), b64(&signature)]
            .join(".")
            .into_bytes()
    }

    /// The example's key, and a signature whose R is the identity point, which has
    /// small order. With s = k·a, where k = SHA-512(R ‖ A ‖ M) and a is the key's
    /// secret scalar, [s]B = R + [k]A holds, so a verifier that does not reject a
    /// small-order R accepts it (ARCHITECTURE §8).
    fn small_order_r() -> Vec<u8> {
        let (key, header, payload) = example_parts();
        let signing_input = format!("{}.{}", b64_json(&header), b64_json(&payload));
        let r = EdwardsPoint::identity().compress().0;
        let k = Sha512::new()
            .chain_update(r)
            .chain_update(key.verifying_key().as_bytes())
            .chain_update(&signing_input)
            .finalize();
        let s = Scalar::from_bytes_mod_order_wide(&k.into()) * key.to_scalar();
        let signature = [r, s.to_bytes()].concat();
        format!("{signing_input}.{}", b64(&signature)).into_bytes()
    }

    /// ARCHITECTURE §8's example of key substitution: the issuer is the example's
    /// `did:key`, but the header carries another key in `jwk`, and that key signed.
    fn embedded_jwk() -> Vec<u8> {
        let (_, mut header, payload) = example_parts();
        let substitute = signing_key("vcrd fixture: a key substituted for the issuer's");
        header["jwk"] = jwk(&substitute);
        sign(&substitute, &header, &payload)
    }

    /// No issuer, and the signer's key in the header's `jwk`: the only key on offer
    /// is one the credential asserts about itself, which vcrd refuses without the
    /// caller's opt-in (REQUIREMENTS §10).
    fn embedded_jwk_only() -> Vec<u8> {
        let (key, mut header, mut payload) = example_parts();
        payload.as_object_mut().unwrap().remove("issuer");
        header["jwk"] = jwk(&key);
        sign(&key, &header, &payload)
    }

    /// The example with `exp` at 2026-06-01, before the tests' clock of 2026-10-01,
    /// while `validUntil` is 2031-01-01: the signature has expired and the credential
    /// has not (VC-JOSE-COSE §3.1.3; RFC 7519 §4.1.4; ARCHITECTURE §10 [S6]).
    fn exp_past() -> Vec<u8> {
        let (key, header, mut payload) = example_parts();
        payload["exp"] = json!(1780272000);
        sign(&key, &header, &payload)
    }

    /// A well-formed `crit` naming an extension vcrd does not implement (RFC 7515
    /// §4.1.11). The `urn:example` namespace is reserved for documentation
    /// (RFC 6963), so the extension has no implementation anywhere. Correctly signed.
    fn crit_unsupported() -> Vec<u8> {
        let (key, mut header, payload) = example_parts();
        header["crit"] = json!(["urn:example:unimplemented"]);
        header["urn:example:unimplemented"] = json!(true);
        sign(&key, &header, &payload)
    }

    /// The curated example's key, header and payload.
    fn example_parts() -> (SigningKey, Value, Value) {
        let key = signing_key("vcrd curated example: Ed25519 issuer");
        let (header, payload) = credential_parts(&did_key(&key));
        (key, header, payload)
    }

    /// The curated example's header and payload, for an issuer that is a `did:key`.
    fn credential_parts(issuer: &str) -> (Value, Value) {
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
        (header, payload)
    }
}

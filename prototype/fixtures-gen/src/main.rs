//! Deterministic fixture minting. Dev-only, never shipped (§11's curated-example
//! rule). Every key comes from a fixed seed, so re-running produces byte-identical
//! output and the committed fixtures stay reviewable in a diff.
//!
//! Negative fixtures come first here for the same reason they come first in the
//! spike: the happy path exercises almost none of the interesting code.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::path::{Path, PathBuf};

const OUT: &str = "fixtures";

fn main() -> Result<()> {
    let out = PathBuf::from(OUT);
    std::fs::create_dir_all(&out).context("create fixtures dir")?;

    let ed = EdKey::from_seed("vcrd-spike/ed25519/issuer");
    let ed_attacker = EdKey::from_seed("vcrd-spike/ed25519/attacker");
    let p256k = P256Key::from_seed("vcrd-spike/p256/issuer");
    let p521k = P521Key::from_seed("vcrd-spike/p521/issuer");
    let rsak = RsaKey::from_seed(b"vcrd-spike/rsa/issuer-seed-0001x");

    let mut manifest: Vec<Value> = Vec::new();

    // ---- 1. alg: none -------------------------------------------------------
    // No signature at all. Must be refused before any key work happens.
    let vc = credential(&ed.did, "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    let tok = format!(
        "{}.{}.",
        b64json(&json!({"alg":"none","typ":"vc+jwt"})),
        b64json(&vc)
    );
    write(&out, "alg-none.jwt", &tok)?;
    manifest.push(json!({"file":"alg-none.jwt","category":"algorithm-confusion",
        "expect":"verify.alg_none","note":"unsigned token claiming a valid issuer"}));

    // ---- 2. algorithm confusion: HS256 keyed with the issuer's public key ----
    // The classic. Only a sharp test because HS256 *is* supported: the rejection has
    // to come from the key type, not from "vcrd cannot do HMAC".
    let vc_p256 = credential(&p256k.did, "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    let header = json!({"alg":"HS256","typ":"vc+jwt"});
    let signing_input = format!("{}.{}", b64json(&header), b64json(&vc_p256));
    let mac = hmac_sha256(&p256k.public_compressed, signing_input.as_bytes());
    write(&out, "alg-confusion-hs256.jwt", &format!("{signing_input}.{}", B64.encode(mac)))?;
    manifest.push(json!({"file":"alg-confusion-hs256.jwt","category":"algorithm-confusion",
        "expect":"verify.alg_key_type_mismatch",
        "note":"HMAC-SHA256 over the token, keyed with the issuer's own P-256 public key bytes"}));

    // ---- 3. embedded jwk, contradicting an independently-resolvable issuer ---
    let vc_ed = credential(&ed.did, "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    let header = json!({"alg":"EdDSA","typ":"vc+jwt","jwk": ed_attacker.jwk()});
    let signing_input = format!("{}.{}", b64json(&header), b64json(&vc_ed));
    let sig = ed_attacker.sign(signing_input.as_bytes());
    write(&out, "embedded-jwk.jwt", &format!("{signing_input}.{}", B64.encode(sig)))?;
    manifest.push(json!({"file":"embedded-jwk.jwt","category":"key-provenance",
        "expect":"verify.signature_invalid",
        "note":"attacker key in the jwk header; issuer is a did:key for a different key"}));

    // ---- 3b. embedded jwk as the *only* key material ------------------------
    // No did:key to fall back to, so the refusal is the whole answer.
    let vc_opaque = credential("https://issuer.example/tenants/42", "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    let header = json!({"alg":"EdDSA","typ":"vc+jwt","jwk": ed_attacker.jwk()});
    let signing_input = format!("{}.{}", b64json(&header), b64json(&vc_opaque));
    let sig = ed_attacker.sign(signing_input.as_bytes());
    write(&out, "embedded-jwk-only.jwt", &format!("{signing_input}.{}", B64.encode(sig)))?;
    manifest.push(json!({"file":"embedded-jwk-only.jwt","category":"key-provenance",
        "expect":"key.embedded_untrusted",
        "note":"self-consistent signature; the only key material is the credential's own"}));

    // ---- 4. expired ---------------------------------------------------------
    let vc = credential(&ed.did, "2019-01-01T00:00:00Z", "2020-01-01T00:00:00Z");
    write(&out, "expired.jwt", &ed.token(&json!({"alg":"EdDSA","typ":"vc+jwt"}), &vc))?;
    manifest.push(json!({"file":"expired.jwt","category":"temporal",
        "expect":"validate.expired","note":"signature is good; only the dates are wrong"}));

    // ---- 5. not yet valid ---------------------------------------------------
    let vc = credential(&ed.did, "2030-01-01T00:00:00Z", "2040-01-01T00:00:00Z");
    write(&out, "not-yet-valid.jwt", &ed.token(&json!({"alg":"EdDSA","typ":"vc+jwt"}), &vc))?;
    manifest.push(json!({"file":"not-yet-valid.jwt","category":"temporal",
        "expect":"validate.not_yet_valid","note":"signature is good"}));

    // ---- 6. tampered --------------------------------------------------------
    // Sign the real credential, then swap the payload for a modified one.
    let vc = credential(&ed.did, "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    let header = json!({"alg":"EdDSA","typ":"vc+jwt"});
    let good_input = format!("{}.{}", b64json(&header), b64json(&vc));
    let sig = ed.sign(good_input.as_bytes());
    let mut tampered_vc = vc.clone();
    tampered_vc["credentialSubject"]["over18"] = json!(true);
    tampered_vc["credentialSubject"]["degree"]["name"] = json!("Doctor of Philosophy");
    write(
        &out,
        "tampered.jwt",
        &format!("{}.{}.{}", b64json(&header), b64json(&tampered_vc), B64.encode(sig)),
    )?;
    manifest.push(json!({"file":"tampered.jwt","category":"integrity",
        "expect":"verify.signature_invalid","note":"a claim was edited after signing"}));

    // ---- 7. unsupported but real algorithm ----------------------------------
    // The signature is deliberately not a real ES256K signature: the point is that
    // rejection must happen by name, before any signature work is attempted.
    let vc = credential(&ed.did, "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    let header = json!({"alg":"ES256K","typ":"vc+jwt"});
    let signing_input = format!("{}.{}", b64json(&header), b64json(&vc));
    write(&out, "unsupported-alg.jwt", &format!("{signing_input}.{}", B64.encode([0u8; 64])))?;
    manifest.push(json!({"file":"unsupported-alg.jwt","category":"unsupported-algorithm",
        "expect":"verify.alg_unsupported",
        "note":"ES256K is a real registered algorithm outside vcrd's set; signature bytes are filler"}));

    // ---- 9. nesting bomb ----------------------------------------------------
    let mut nested = json!("bottom");
    for _ in 0..64 {
        nested = json!({ "n": nested });
    }
    let mut vc = credential(&ed.did, "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    vc["credentialSubject"]["nested"] = nested;
    write(&out, "deep-nesting.jwt", &ed.token(&json!({"alg":"EdDSA","typ":"vc+jwt"}), &vc))?;
    manifest.push(json!({"file":"deep-nesting.jwt","category":"resource-limits",
        "expect":"parse.nesting_too_deep","note":"66 levels of nesting inside credentialSubject"}));

    // ---- 10. VCDM 1.1 JWT mapping, with a disagreement ----------------------
    // exp says 2030; the inner expirationDate says 2035. Both are "the" expiry.
    let inner = json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "ExampleDegreeCredential"],
        "issuer": ed.did,
        "issuanceDate": "2024-01-01T00:00:00Z",
        "expirationDate": "2035-01-01T00:00:00Z",
        "credentialSubject": subject(),
    });
    let payload = json!({
        "iss": ed.did,
        "sub": "did:example:holder-1",
        "jti": "urn:uuid:5c2a1f60-0000-4000-8000-000000000001",
        "nbf": 1_704_067_200i64,
        "exp": 1_893_456_000i64,
        "vc": inner,
    });
    write(&out, "vcdm11-mapping.jwt", &ed.token(&json!({"alg":"EdDSA","typ":"JWT"}), &payload))?;
    manifest.push(json!({"file":"vcdm11-mapping.jwt","category":"profile",
        "expect":"validate.profile_not_implemented",
        "note":"registered exp = 2030-01-01, inner expirationDate = 2035-01-01"}));

    // ---- 11. controls -------------------------------------------------------
    let vc = credential(&ed.did, "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    write(&out, "happy-ed25519.jwt", &ed.token(&json!({"alg":"EdDSA","typ":"vc+jwt"}), &vc))?;
    manifest.push(json!({"file":"happy-ed25519.jwt","category":"control","expect":"verified"}));

    let vc = credential(&p256k.did, "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    write(&out, "happy-es256.jwt", &p256k.token(&json!({"alg":"ES256","typ":"vc+jwt"}), &vc))?;
    manifest.push(json!({"file":"happy-es256.jwt","category":"control","expect":"verified",
        "note":"also the allowlist-rejection case, run with --allow-alg EdDSA"}));

    let vc = credential(&p521k.did, "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    write(&out, "happy-es512.jwt", &p521k.token(&json!({"alg":"ES512","typ":"vc+jwt"}), &vc))?;
    manifest.push(json!({"file":"happy-es512.jwt","category":"control","expect":"verified",
        "note":"ES512/P-521 -- the EUDI interop case that blocked two of three JOSE crates"}));

    // RSA has no did:key codec support here, so this one resolves through the
    // caller-supplied JWK set instead -- the only fixture that exercises that path.
    let vc = credential("https://issuer.example/rsa", "2024-01-01T00:00:00Z", "2035-01-01T00:00:00Z");
    write(
        &out,
        "happy-rs256.jwt",
        &rsak.token(&json!({"alg":"RS256","typ":"vc+jwt","kid":"issuer-rsa-1"}), &vc),
    )?;
    manifest.push(json!({"file":"happy-rs256.jwt","category":"control","expect":"verified",
        "note":"needs --jwks fixtures/caller-jwks.json; did:key has no RSA codec here"}));

    // Caller-supplied key material.
    let mut jwks = rsak.jwk();
    jwks["kid"] = json!("issuer-rsa-1");
    std::fs::write(out.join("caller-jwks.json"), format!("{:#}\n", json!({"keys": [jwks]})))?;

    std::fs::write(out.join("MANIFEST.json"), format!("{:#}\n", json!({"fixtures": manifest})))?;

    println!("wrote {} fixtures to {}", manifest.len(), out.display());
    println!("ed25519 issuer: {}", ed.did);
    println!("ed25519 attacker: {}", ed_attacker.did);
    println!("p256 issuer:    {}", p256k.did);
    println!("p521 issuer:    {}", p521k.did);
    Ok(())
}

// ---------------------------------------------------------------------------

fn subject() -> Value {
    json!({
        "id": "did:example:holder-1",
        "name": "Sam Rivera-Testcase",
        "birthDate": "1985-03-14",
        "nationality": "NL",
        "over18": true,
        "licenseClass": "B",
        "degree": {
            "type": "ExampleBachelorDegree",
            "name": "Bachelor of Science and Arts"
        }
    })
}

fn credential(issuer: &str, from: &str, until: &str) -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:5c2a1f60-0000-4000-8000-000000000000",
        "type": ["VerifiableCredential", "ExampleDegreeCredential"],
        "issuer": issuer,
        "validFrom": from,
        "validUntil": until,
        "credentialSubject": subject(),
    })
}

fn b64json(v: &Value) -> String {
    B64.encode(serde_json::to_vec(v).unwrap_or_default())
}

fn write(dir: &Path, name: &str, token: &str) -> Result<()> {
    std::fs::write(dir.join(name), format!("{token}\n")).with_context(|| format!("write {name}"))?;
    Ok(())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn did_key(codec: u64, key_bytes: &[u8]) -> String {
    let mut buf = unsigned_varint::encode::u64_buffer();
    let prefix = unsigned_varint::encode::u64(codec, &mut buf);
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(key_bytes);
    format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, bytes))
}

// ---------------------------------------------------------------------------

struct EdKey {
    sk: ed25519_dalek::SigningKey,
    did: String,
}

impl EdKey {
    fn from_seed(label: &str) -> Self {
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let did = did_key(0xed, sk.verifying_key().as_bytes());
        EdKey { sk, did }
    }
    fn jwk(&self) -> Value {
        json!({"kty":"OKP","crv":"Ed25519","x": B64.encode(self.sk.verifying_key().as_bytes())})
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.sk.sign(msg).to_bytes().to_vec()
    }
    fn token(&self, header: &Value, payload: &Value) -> String {
        let si = format!("{}.{}", b64json(header), b64json(payload));
        format!("{si}.{}", B64.encode(self.sign(si.as_bytes())))
    }
}

struct P256Key {
    sk: p256::ecdsa::SigningKey,
    did: String,
    public_compressed: Vec<u8>,
}

impl P256Key {
    fn from_seed(label: &str) -> Self {
        let bytes: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        let sk = p256::ecdsa::SigningKey::from_slice(&bytes).expect("seeded scalar is in range");
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let compressed = sk.verifying_key().as_affine().to_encoded_point(true).as_bytes().to_vec();
        let did = did_key(0x1200, &compressed);
        P256Key { sk, did, public_compressed: compressed }
    }
    fn token(&self, header: &Value, payload: &Value) -> String {
        use p256::ecdsa::signature::Signer;
        let si = format!("{}.{}", b64json(header), b64json(payload));
        let sig: p256::ecdsa::Signature = self.sk.sign(si.as_bytes());
        format!("{si}.{}", B64.encode(sig.to_bytes()))
    }
}

struct P521Key {
    sk: p521::ecdsa::SigningKey,
    did: String,
}

impl P521Key {
    fn from_seed(label: &str) -> Self {
        // 66 bytes with the top two zeroed keeps the scalar well below the P-521 order.
        let mut bytes = vec![0u8, 0u8];
        bytes.extend_from_slice(&Sha512::digest(label.as_bytes()));
        let sk = p521::ecdsa::SigningKey::from_slice(&bytes).expect("seeded scalar is in range");
        // FINDING (question 5): `SigningKey::verifying_key()` exists in p521 0.13.3 but
        // is gated on a `verifying` feature the crate does not declare, so it cannot be
        // called at all. `VerifyingKey::from(&sk)` is the only route.
        let vk = p521::ecdsa::VerifyingKey::from(&sk);
        let compressed = vk.to_encoded_point(true).as_bytes().to_vec();
        let did = did_key(0x1202, &compressed);
        P521Key { sk, did }
    }
    fn token(&self, header: &Value, payload: &Value) -> String {
        // FINDING (question 5): p521 0.13.3 has no RFC6979 support -- its `Signer` impl
        // delegates to `RandomizedSigner` with `OsRng`, so P-521 signatures are
        // non-deterministic, unlike its p256 sibling. Seeding the RNG explicitly is the
        // only way to mint a reproducible fixture.
        use p521::ecdsa::signature::RandomizedSigner;
        use rand_core::SeedableRng;
        let si = format!("{}.{}", b64json(header), b64json(payload));
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x51u8; 32]);
        let sig: p521::ecdsa::Signature = self
            .sk
            .try_sign_with_rng(&mut rng, si.as_bytes())
            .expect("p521 sign");
        format!("{si}.{}", B64.encode(sig.to_bytes()))
    }
}

struct RsaKey {
    sk: rsa::RsaPrivateKey,
}

impl RsaKey {
    fn from_seed(seed: &[u8; 32]) -> Self {
        use rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
        let sk = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        RsaKey { sk }
    }
    fn jwk(&self) -> Value {
        use rsa::traits::PublicKeyParts;
        let pk = self.sk.to_public_key();
        json!({
            "kty": "RSA",
            "n": B64.encode(pk.n().to_bytes_be()),
            "e": B64.encode(pk.e().to_bytes_be()),
        })
    }
    fn token(&self, header: &Value, payload: &Value) -> String {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        let si = format!("{}.{}", b64json(header), b64json(payload));
        let sk = SigningKey::<Sha256>::new(self.sk.clone());
        let sig = sk.sign(si.as_bytes());
        format!("{si}.{}", B64.encode(sig.to_bytes()))
    }
}

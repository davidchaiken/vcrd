//! Helpers shared by the verify tests. Each test file declares this module under
//! `#[cfg(test)]`, so that the workspace's panic lints exempt it as they do test
//! functions (docs/reviews/milestone-0.md, gap 1).

// Each test file uses a subset of these helpers.
#![allow(dead_code)]

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::macros::datetime;
use vcrd_core::{
    Attribution, Context, FixedClock, KeyPolicy, KeySet, KeySetChecks, KeySetError, Limits,
    ProofResult, Registry, Report, Severity, verify,
};

/// The tests' clock, 2026-10-01T00:00:00Z, in seconds since the Unix epoch.
pub const NOW: i64 = 1790812800;

fn key() -> SigningKey {
    seeded("vcrd-core verify tests: issuer")
}

fn seeded(seed: &str) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(seed.as_bytes()).into())
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn jwk_of(key: &SigningKey) -> Value {
    json!({"kty": "OKP", "crv": "Ed25519", "x": b64(key.verifying_key().as_bytes())})
}

/// The issuer's key as a JWK (RFC 8037 §2).
pub fn issuer_jwk() -> Value {
    jwk_of(&key())
}

/// The issuer's `did:key`, and the `kid` [`signed`] gives the header: the DID URL of
/// its one key.
pub fn issuer_did_and_kid() -> (String, String) {
    let multibase = format!(
        "z{}",
        bs58::encode([&[0xed, 0x01][..], key().verifying_key().as_bytes()].concat()).into_string()
    );
    let issuer = format!("did:key:{multibase}");
    let kid = format!("{issuer}#{multibase}");
    (issuer, kid)
}

fn other_key() -> SigningKey {
    seeded("vcrd-core verify tests: other")
}

/// Another key, which signs only what [`signed_by_other`] signs, as a JWK.
pub fn other_jwk() -> Value {
    jwk_of(&other_key())
}

/// An Ed25519 key that signs nothing, one for each `n`, as a JWK.
pub fn unused_jwk(n: u8) -> Value {
    jwk_of(&seeded(&format!("vcrd-core verify tests: unused {n}")))
}

/// An Ed448 public key as a JWK (RFC 8037 §2): a key type vcrd names and cannot use.
pub fn ed448_jwk() -> Value {
    json!({"kty": "OKP", "crv": "Ed448", "x": b64(&[9; 57])})
}

/// A symmetric key as a JWK (RFC 7518 §6.4), which vcrd does not yet use.
pub fn oct_jwk() -> Value {
    json!({"kty": "oct", "k": "c2VjcmV0IGtleSBtYXRlcmlhbA"})
}

/// A credential with a `did:key` issuer, its header and payload changed by `edit`,
/// signed by the issuer's key. Its `alg` is `Ed25519`, not the deprecated `EdDSA`,
/// so that each test's findings are those of its own condition (RFC 9864).
pub fn signed(edit: impl FnOnce(&mut Value, &mut Value)) -> Vec<u8> {
    signed_by(&key(), edit)
}

/// As [`signed`], signed by the other key rather than the issuer's.
pub fn signed_by_other(edit: impl FnOnce(&mut Value, &mut Value)) -> Vec<u8> {
    signed_by(&other_key(), edit)
}

fn signed_by(key: &SigningKey, edit: impl FnOnce(&mut Value, &mut Value)) -> Vec<u8> {
    let (issuer, kid) = issuer_did_and_kid();
    let mut header = json!({
        "alg": "Ed25519",
        "cty": "vc",
        "kid": kid,
        "typ": "vc+jwt",
    });
    let mut payload = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": issuer,
        "credentialSubject": {"id": "did:example:subject", "name": "a name"},
    });
    edit(&mut header, &mut payload);
    let signing_input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(payload.to_string().as_bytes())
    );
    let signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64(&signature.to_bytes())).into_bytes()
}

pub fn verified(bytes: &[u8]) -> Report {
    verified_with_skew(bytes, 0)
}

pub fn verified_with_skew(bytes: &[u8], skew_seconds: u64) -> Report {
    let ctx = Context::builder(FixedClock(datetime!(2026-10-01 0:00 UTC)))
        .clock_skew(Duration::from_secs(skew_seconds))
        .build();
    verify(bytes, &ctx, &Registry::builtin())
}

/// Verified with the caller's opt-in to an embedded key alone (ARCHITECTURE §8,
/// rule 2).
pub fn verified_opted_in(bytes: &[u8]) -> Report {
    let policy = KeyPolicy {
        allow_embedded_key_alone: true,
        ..KeyPolicy::default()
    };
    let ctx = Context::builder(FixedClock(datetime!(2026-10-01 0:00 UTC)))
        .key_policy(policy)
        .build();
    verify(bytes, &ctx, &Registry::builtin())
}

/// Verified with `key_set`, a JWK Set (RFC 7517 §5), as the caller's keys, checked
/// strictly, the default.
pub fn verified_with_key_set(bytes: &[u8], key_set: &Value) -> Report {
    verified_with(bytes, key_set, KeyPolicy::default(), KeySetChecks::Strict)
}

/// Verified with `key_set` checked leniently.
pub fn verified_leniently(bytes: &[u8], key_set: &Value) -> Report {
    verified_with(bytes, key_set, KeyPolicy::default(), KeySetChecks::Lenient)
}

/// Verified with the caller's opt-in to letting its key override the issuer key
/// (ARCHITECTURE §8, rule 1), or without it.
pub fn verified_overriding(bytes: &[u8], key_set: &Value, override_: bool) -> Report {
    let policy = KeyPolicy {
        allow_caller_key_override: override_,
        ..KeyPolicy::default()
    };
    verified_with(bytes, key_set, policy, KeySetChecks::Strict)
}

/// `key_set` as [`KeySet::parse`] reads it.
pub fn read(key_set: &Value, checks: KeySetChecks) -> Result<KeySet, KeySetError> {
    KeySet::parse(key_set.to_string().as_bytes(), &Limits::default(), checks)
}

/// Verified with `key_set`, which must be read without error, the caller's policy and
/// the checks given.
pub fn verified_with(
    bytes: &[u8],
    key_set: &Value,
    policy: KeyPolicy,
    checks: KeySetChecks,
) -> Report {
    let key_set = read(key_set, checks).unwrap();
    let ctx = Context::builder(FixedClock(datetime!(2026-10-01 0:00 UTC)))
        .key_set(key_set)
        .key_policy(policy)
        .build();
    verify(bytes, &ctx, &Registry::builtin())
}

/// The one proof's result, and every finding as (code, attribution, severity).
pub fn proof_of(report: &Report) -> (&ProofResult, Vec<(&'static str, Attribution, Severity)>) {
    let verified = report.verify.output().expect("verify ran");
    let [proof] = verified.proofs.as_slice() else {
        panic!("one proof: {report:?}")
    };
    let findings = report
        .findings()
        .map(|f| (f.code, f.attribution, f.severity))
        .collect();
    (proof, findings)
}

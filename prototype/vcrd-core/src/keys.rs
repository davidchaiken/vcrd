//! Key material, its provenance, and the precedence rules between sources
//! (prototype question 6).
//!
//! The bypass this guards against: a JWT can carry a public key in its own `jwk`
//! header. Verifying against it proves only that whoever wrote the credential owns
//! the matching private key -- which an attacker does. Honouring an embedded key
//! without pinning it to an independently-established issuer key is a complete
//! verification bypass, so provenance is a first-class part of the answer, not a
//! footnote.

use crate::model::{Blame, Finding, FindingDetail, Tier};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::Value;
use sha2::{Digest, Sha256};

// NOTE (finding, question 5): `p521::ecdsa::VerifyingKey` does not implement `Debug`
// in the 0.13 line, unlike its p256 sibling. A hand-written impl is needed -- a small
// but real sign of how much less exercised the P-521 path is.
#[derive(Clone)]
pub enum VerifyKey {
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
    P256(Box<p256::ecdsa::VerifyingKey>),
    P521(Box<p521::ecdsa::VerifyingKey>),
    Rsa(Box<rsa::RsaPublicKey>),
    Octet(Vec<u8>),
}

impl std::fmt::Debug for VerifyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerifyKey({})", self.kind())
    }
}

impl VerifyKey {
    pub fn kind(&self) -> &'static str {
        match self {
            VerifyKey::Ed25519(_) => "OKP/Ed25519",
            VerifyKey::P256(_) => "EC/P-256",
            VerifyKey::P521(_) => "EC/P-521",
            VerifyKey::Rsa(_) => "RSA",
            VerifyKey::Octet(_) => "oct",
        }
    }
}

/// Where the format says key material might be found. Populated by the format, acted
/// on by the resolver -- the format never decides what to trust.
#[derive(Clone, Debug, Default)]
pub struct KeyHints {
    pub kid: Option<String>,
    pub issuer: Option<String>,
    pub embedded_jwk: Option<Value>,
    pub embedded_x5c: bool,
}

#[derive(Clone, Debug)]
pub enum ResolutionMethod {
    /// A `did:key` in the credential's `issuer`/`iss`. Self-certifying: the identifier
    /// *is* the key, so an attacker cannot swap the key without changing the issuer.
    DidKey { did: String },
    /// A key the caller supplied out of band.
    CallerSuppliedJwkSet { kid: Option<String> },
    /// An embedded key that turned out to equal an independently-resolved one.
    /// Safe, because the independent resolution is what established it.
    EmbeddedPinnedToResolved { thumbprint: String },
}

impl ResolutionMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResolutionMethod::DidKey { .. } => "did:key",
            ResolutionMethod::CallerSuppliedJwkSet { .. } => "caller_supplied_jwk_set",
            ResolutionMethod::EmbeddedPinnedToResolved { .. } => "embedded_pinned_to_resolved",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EmbeddedKeyLocation {
    HeaderJwk,
    HeaderX5c,
}

impl EmbeddedKeyLocation {
    pub fn as_str(self) -> &'static str {
        match self {
            EmbeddedKeyLocation::HeaderJwk => "header.jwk",
            EmbeddedKeyLocation::HeaderX5c => "header.x5c",
        }
    }
}

/// The distinction the result schema has to be able to state.
#[derive(Clone, Debug)]
pub enum KeyProvenance {
    /// Key material established without trusting the credential's own contents.
    IndependentlyResolved { via: ResolutionMethod, thumbprint: String },
    /// Key material the credential supplied about itself. `accepted` is only ever
    /// true when the caller explicitly opted in, and the result says so.
    CredentialSupplied { location: EmbeddedKeyLocation, thumbprint: String, accepted: bool },
    /// No key material at all.
    None,
}

impl KeyProvenance {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyProvenance::IndependentlyResolved { .. } => "independently_resolved",
            KeyProvenance::CredentialSupplied { .. } => "credential_supplied",
            KeyProvenance::None => "none",
        }
    }
    /// The single boolean a risk layer built on top of vcrd would actually branch on.
    pub fn is_independent(&self) -> bool {
        matches!(self, KeyProvenance::IndependentlyResolved { .. })
    }
}

/// Caller-supplied key material. Injected, never fetched (§6).
pub trait KeyStore: std::fmt::Debug {
    fn by_kid(&self, kid: &str) -> Option<Value>;
    fn sole(&self) -> Option<Value>;
}

#[derive(Clone, Debug, Default)]
pub struct EmptyKeyStore;

impl KeyStore for EmptyKeyStore {
    fn by_kid(&self, _kid: &str) -> Option<Value> {
        None
    }
    fn sole(&self) -> Option<Value> {
        None
    }
}

#[derive(Clone, Debug, Default)]
pub struct JwkSetStore {
    pub keys: Vec<Value>,
}

impl KeyStore for JwkSetStore {
    fn by_kid(&self, kid: &str) -> Option<Value> {
        self.keys
            .iter()
            .find(|k| k.get("kid").and_then(Value::as_str) == Some(kid))
            .cloned()
    }
    fn sole(&self) -> Option<Value> {
        match self.keys.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        }
    }
}

pub struct Resolved {
    pub key: Option<VerifyKey>,
    pub provenance: KeyProvenance,
    pub findings: Vec<Finding>,
}

/// Breakpoint anchor for prototype question 6.
///
/// Precedence, highest first:
///   1. caller-supplied JWK set, matched by `kid` (or the sole key)
///   2. `did:key` in the issuer -- self-certifying, so still independent
///   3. an embedded `jwk`, *only* if it matches something from 1 or 2 (pinning)
///   4. an embedded `jwk` with an explicit caller opt-in, marked in the result
///
/// An embedded key with no opt-in and no match is refused, and that refusal is the
/// finding -- not a silent fallback to "no key material".
#[inline(never)]
pub fn resolve(hints: &KeyHints, store: &dyn KeyStore, trust_embedded: bool) -> Resolved {
    let mut findings = Vec::new();
    let mut looked_at: Vec<&'static str> = Vec::new();

    // 1. caller-supplied key material.
    looked_at.push("caller_supplied_jwk_set");
    let caller_jwk = hints
        .kid
        .as_deref()
        .and_then(|k| store.by_kid(k))
        .or_else(|| store.sole());

    let mut independent: Option<(VerifyKey, ResolutionMethod, String)> = None;

    if let Some(jwk) = &caller_jwk {
        match jwk_to_key(jwk) {
            Ok(k) => {
                let tp = thumbprint(jwk).unwrap_or_default();
                independent = Some((k, ResolutionMethod::CallerSuppliedJwkSet { kid: hints.kid.clone() }, tp));
            }
            Err(reason) => findings.push(Finding::warn(
                "key.caller_jwk_unsupported",
                Tier::Verify,
                Blame::Environment,
                FindingDetail::JwkUnsupported { reason },
            )),
        }
    }

    // 2. did:key in the issuer.
    if independent.is_none() {
        looked_at.push("issuer_did_key");
        if let Some(iss) = hints.issuer.as_deref()
            && iss.starts_with("did:key:") {
                match decode_did_key(iss) {
                    Ok((key, jwk)) => {
                        let tp = thumbprint(&jwk).unwrap_or_default();
                        independent = Some((key, ResolutionMethod::DidKey { did: iss.to_string() }, tp));
                    }
                    Err(DidKeyError::Undecodable(reason)) => findings.push(Finding::error(
                        "key.did_key_undecodable",
                        Tier::Verify,
                        Blame::Input,
                        FindingDetail::DidKeyUndecodable { did: iss.to_string(), reason },
                    )),
                    Err(DidKeyError::CodecUnsupported { codec, name }) => findings.push(Finding::error(
                        "key.did_key_codec_unsupported",
                        Tier::Verify,
                        Blame::Vcrd,
                        FindingDetail::DidKeyCodecUnsupported { did: iss.to_string(), codec, codec_name: name },
                    )),
                }
            }
    }

    // 3 / 4. the embedded key.
    if let Some(embedded) = &hints.embedded_jwk {
        looked_at.push("header.jwk");
        let embedded_tp = thumbprint(embedded).unwrap_or_default();

        if let Some((key, method, tp)) = independent {
            if !embedded_tp.is_empty() && embedded_tp == tp {
                findings.push(Finding::warn(
                    "key.embedded_pinned",
                    Tier::Verify,
                    Blame::Input,
                    FindingDetail::EmbeddedKeyPinned {
                        location: EmbeddedKeyLocation::HeaderJwk.as_str(),
                        thumbprint: embedded_tp.clone(),
                    },
                ));
            } else {
                // Independent material exists and disagrees. Use the independent key;
                // do not let the credential redirect us to its own.
                findings.push(Finding::warn(
                    "key.embedded_ignored_independent_available",
                    Tier::Verify,
                    Blame::Input,
                    FindingDetail::EmbeddedKeyUntrusted {
                        location: EmbeddedKeyLocation::HeaderJwk.as_str(),
                        thumbprint: embedded_tp,
                    },
                ));
            }
            return Resolved {
                key: Some(key),
                provenance: KeyProvenance::IndependentlyResolved { via: method, thumbprint: tp },
                findings,
            };
        }

        // No independent material at all.
        if trust_embedded {
            match jwk_to_key(embedded) {
                Ok(k) => {
                    findings.push(Finding::warn(
                        "key.embedded_accepted_by_flag",
                        Tier::Verify,
                        Blame::Policy,
                        FindingDetail::EmbeddedKeyAcceptedByFlag {
                            location: EmbeddedKeyLocation::HeaderJwk.as_str(),
                            thumbprint: embedded_tp.clone(),
                        },
                    ));
                    return Resolved {
                        key: Some(k),
                        provenance: KeyProvenance::CredentialSupplied {
                            location: EmbeddedKeyLocation::HeaderJwk,
                            thumbprint: embedded_tp,
                            accepted: true,
                        },
                        findings,
                    };
                }
                Err(reason) => findings.push(Finding::error(
                    "key.embedded_jwk_unsupported",
                    Tier::Verify,
                    Blame::Input,
                    FindingDetail::JwkUnsupported { reason },
                )),
            }
        } else {
            findings.push(Finding::error(
                "key.embedded_untrusted",
                Tier::Verify,
                Blame::Input,
                FindingDetail::EmbeddedKeyUntrusted {
                    location: EmbeddedKeyLocation::HeaderJwk.as_str(),
                    thumbprint: embedded_tp.clone(),
                },
            ));
            return Resolved {
                key: None,
                provenance: KeyProvenance::CredentialSupplied {
                    location: EmbeddedKeyLocation::HeaderJwk,
                    thumbprint: embedded_tp,
                    accepted: false,
                },
                findings,
            };
        }
    }

    if hints.embedded_x5c {
        looked_at.push("header.x5c");
    }

    match independent {
        Some((key, method, tp)) => Resolved {
            key: Some(key),
            provenance: KeyProvenance::IndependentlyResolved { via: method, thumbprint: tp },
            findings,
        },
        None => {
            findings.push(Finding::error(
                "key.none_available",
                Tier::Verify,
                Blame::Environment,
                FindingDetail::NoKeyMaterial { looked_at },
            ));
            Resolved { key: None, provenance: KeyProvenance::None, findings }
        }
    }
}

// ---------------------------------------------------------------------------
// did:key
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum DidKeyError {
    Undecodable(String),
    CodecUnsupported { codec: u64, name: &'static str },
}

/// Every multicodec vcrd can *decode*. Whether it can then *verify* with the result
/// is a separate question, and the gap between the two lists is a finding.
pub const KNOWN_CODECS: &[(u64, &str, bool)] = &[
    (0xed, "ed25519-pub", true),
    (0x1200, "p256-pub", true),
    (0x1201, "p384-pub", false),
    (0x1202, "p521-pub", true),
    (0xe7, "secp256k1-pub", false),
    (0x1205, "rsa-pub", false),
];

pub fn codec_name(code: u64) -> &'static str {
    KNOWN_CODECS
        .iter()
        .find(|(c, _, _)| *c == code)
        .map(|(_, n, _)| *n)
        .unwrap_or("unknown")
}

/// Decode `did:key:z...` to a verifying key plus the equivalent JWK (for thumbprints).
pub fn decode_did_key(did: &str) -> Result<(VerifyKey, Value), DidKeyError> {
    let mb = did.strip_prefix("did:key:").ok_or_else(|| DidKeyError::Undecodable("not a did:key".into()))?;
    let mb = mb.split(['#', '?']).next().unwrap_or(mb);

    let (_base, bytes) = multibase::decode(mb).map_err(|e| DidKeyError::Undecodable(format!("multibase: {e}")))?;

    let (code, rest) = unsigned_varint::decode::u64(&bytes)
        .map_err(|e| DidKeyError::Undecodable(format!("multicodec varint: {e}")))?;

    match code {
        0xed => {
            let arr: [u8; 32] = rest
                .try_into()
                .map_err(|_| DidKeyError::Undecodable(format!("ed25519 key is {} bytes, expected 32", rest.len())))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map_err(|e| DidKeyError::Undecodable(format!("ed25519: {e}")))?;
            let jwk = serde_json::json!({
                "kty": "OKP", "crv": "Ed25519", "x": B64.encode(arr)
            });
            Ok((VerifyKey::Ed25519(Box::new(vk)), jwk))
        }
        0x1200 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(rest)
                .map_err(|e| DidKeyError::Undecodable(format!("p256 sec1: {e}")))?;
            let jwk = p256_jwk(&vk);
            Ok((VerifyKey::P256(Box::new(vk)), jwk))
        }
        0x1202 => {
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(rest)
                .map_err(|e| DidKeyError::Undecodable(format!("p521 sec1: {e}")))?;
            let jwk = p521_jwk(&vk);
            Ok((VerifyKey::P521(Box::new(vk)), jwk))
        }
        other => Err(DidKeyError::CodecUnsupported { codec: other, name: codec_name(other) }),
    }
}

fn p256_jwk(vk: &p256::ecdsa::VerifyingKey) -> Value {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let pt = vk.as_affine().to_encoded_point(false);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": B64.encode(pt.x().map(|b| b.to_vec()).unwrap_or_default()),
        "y": B64.encode(pt.y().map(|b| b.to_vec()).unwrap_or_default()),
    })
}

fn p521_jwk(vk: &p521::ecdsa::VerifyingKey) -> Value {
    use p521::elliptic_curve::sec1::ToEncodedPoint;
    let pt = vk.as_affine().to_encoded_point(false);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-521",
        "x": B64.encode(pt.x().map(|b| b.to_vec()).unwrap_or_default()),
        "y": B64.encode(pt.y().map(|b| b.to_vec()).unwrap_or_default()),
    })
}

// ---------------------------------------------------------------------------
// JWK
// ---------------------------------------------------------------------------

pub fn jwk_to_key(jwk: &Value) -> Result<VerifyKey, String> {
    let kty = jwk.get("kty").and_then(Value::as_str).ok_or("jwk has no kty")?;
    match kty {
        "OKP" => {
            let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or("");
            if crv != "Ed25519" {
                return Err(format!("unsupported OKP curve {crv}"));
            }
            let x = b64_field(jwk, "x")?;
            let arr: [u8; 32] = x.as_slice().try_into().map_err(|_| "Ed25519 x is not 32 bytes".to_string())?;
            ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map(|k| VerifyKey::Ed25519(Box::new(k)))
                .map_err(|e| e.to_string())
        }
        "EC" => {
            let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or("");
            let x = b64_field(jwk, "x")?;
            let y = b64_field(jwk, "y")?;
            let mut sec1 = vec![0x04u8];
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            match crv {
                "P-256" => p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map(|k| VerifyKey::P256(Box::new(k)))
                    .map_err(|e| e.to_string()),
                "P-521" => p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map(|k| VerifyKey::P521(Box::new(k)))
                    .map_err(|e| e.to_string()),
                other => Err(format!("unsupported EC curve {other}")),
            }
        }
        "RSA" => {
            use rsa::BigUint;
            let n = b64_field(jwk, "n")?;
            let e = b64_field(jwk, "e")?;
            rsa::RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
                .map(|k| VerifyKey::Rsa(Box::new(k)))
                .map_err(|e| e.to_string())
        }
        "oct" => Ok(VerifyKey::Octet(b64_field(jwk, "k")?)),
        other => Err(format!("unsupported kty {other}")),
    }
}

fn b64_field(jwk: &Value, name: &str) -> Result<Vec<u8>, String> {
    let s = jwk.get(name).and_then(Value::as_str).ok_or(format!("jwk has no {name}"))?;
    B64.decode(s).map_err(|e| format!("jwk {name} is not base64url: {e}"))
}

/// RFC 7638 JWK thumbprint. Pinning an embedded key to a resolved one needs a
/// canonical identity for a key, and this is the standard one.
pub fn thumbprint(jwk: &Value) -> Option<String> {
    let kty = jwk.get("kty")?.as_str()?;
    let canonical = match kty {
        "OKP" => format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
            jwk.get("crv")?.as_str()?,
            jwk.get("x")?.as_str()?
        ),
        "EC" => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk.get("crv")?.as_str()?,
            jwk.get("x")?.as_str()?,
            jwk.get("y")?.as_str()?
        ),
        "RSA" => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            jwk.get("e")?.as_str()?,
            jwk.get("n")?.as_str()?
        ),
        "oct" => format!(r#"{{"k":"{}","kty":"oct"}}"#, jwk.get("k")?.as_str()?),
        _ => return None,
    };
    Some(B64.encode(Sha256::digest(canonical.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_key_is_refused_without_opt_in() {
        let jwk = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
        let hints = KeyHints { embedded_jwk: Some(jwk), ..Default::default() };
        let r = resolve(&hints, &EmptyKeyStore, false);
        assert!(r.key.is_none(), "embedded key was used without opt-in");
        assert!(!r.provenance.is_independent());
        assert!(r.findings.iter().any(|f| f.code == "key.embedded_untrusted"));
    }

    #[test]
    fn independent_key_wins_over_embedded() {
        // did:key for a real Ed25519 key, plus a *different* embedded key.
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let other = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
        let hints = KeyHints {
            issuer: Some(did.into()),
            embedded_jwk: Some(other),
            ..Default::default()
        };
        let r = resolve(&hints, &EmptyKeyStore, false);
        assert!(r.key.is_some());
        assert!(r.provenance.is_independent(), "provenance: {:?}", r.provenance);
    }

    #[test]
    fn codec_decode_and_verify_lists_are_tracked_separately() {
        // The gap is deliberate and reported; this test just pins it down.
        let decodable: Vec<&str> = KNOWN_CODECS.iter().map(|(_, n, _)| *n).collect();
        let verifiable: Vec<&str> = KNOWN_CODECS.iter().filter(|(_, _, v)| *v).map(|(_, n, _)| *n).collect();
        assert!(decodable.len() > verifiable.len());
    }
}

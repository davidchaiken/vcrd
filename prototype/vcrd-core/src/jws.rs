//! Hand-rolled JWS compact verification (prototype question 5).
//!
//! The requirement this exists to satisfy: "verified", "vcrd does not support that
//! algorithm", "your policy forbids that algorithm", and "that algorithm cannot be
//! used with that key" must be four *structurally distinct* outcomes (§10). Most
//! JOSE crates collapse at least two of them into one opaque error type.
//!
//! Second requirement: the algorithm is chosen by caller policy first. The header's
//! `alg` is attacker-controlled input that gets *checked*, never obeyed.

use crate::keys::VerifyKey;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::Value;

/// Everything vcrd will verify, in registry order. Deliberately includes HS256 so
/// the algorithm-confusion fixture is rejected on key-type grounds rather than
/// trivially as "unsupported" -- which would be a much weaker test.
pub const SUPPORTED_ALGS: &[&str] = &["EdDSA", "ES256", "ES512", "RS256", "HS256"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    EdDsa,
    Es256,
    Es512,
    Rs256,
    Hs256,
}

impl Alg {
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::EdDsa => "EdDSA",
            Alg::Es256 => "ES256",
            Alg::Es512 => "ES512",
            Alg::Rs256 => "RS256",
            Alg::Hs256 => "HS256",
        }
    }

    fn from_name(s: &str) -> Option<Alg> {
        match s {
            "EdDSA" => Some(Alg::EdDsa),
            "ES256" => Some(Alg::Es256),
            "ES512" => Some(Alg::Es512),
            "RS256" => Some(Alg::Rs256),
            "HS256" => Some(Alg::Hs256),
            _ => None,
        }
    }

    /// The key kind this algorithm requires. Enforcing this is the structural
    /// defence against the whole algorithm-confusion class.
    pub fn required_key_kind(self) -> &'static str {
        match self {
            Alg::EdDsa => "OKP/Ed25519",
            Alg::Es256 => "EC/P-256",
            Alg::Es512 => "EC/P-521",
            Alg::Rs256 => "RSA",
            Alg::Hs256 => "oct",
        }
    }
}

/// The caller's algorithm policy (§10). `None` means "vcrd's full supported set".
#[derive(Clone, Debug, Default)]
pub struct AlgPolicy {
    pub allowed: Option<Vec<String>>,
}

impl AlgPolicy {
    pub fn allow_all() -> Self {
        AlgPolicy { allowed: None }
    }
    pub fn allow(names: Vec<String>) -> Self {
        AlgPolicy { allowed: Some(names) }
    }
    pub fn permits(&self, name: &str) -> bool {
        match &self.allowed {
            None => true,
            Some(list) => list.iter().any(|a| a == name),
        }
    }
    pub fn allowed_names(&self) -> Vec<String> {
        match &self.allowed {
            None => SUPPORTED_ALGS.iter().map(|s| s.to_string()).collect(),
            Some(list) => list.clone(),
        }
    }
}

/// The outcome of algorithm selection. Note that `Rejected` carries a *list*: an
/// algorithm can be both unsupported by vcrd and forbidden by the caller, and
/// collapsing that into one reason throws away half the answer.
#[derive(Clone, Debug)]
pub enum AlgDecision {
    Use(Alg),
    Rejected(Vec<AlgRejection>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlgRejection {
    /// `alg: none`. Never acceptable, never a policy question.
    None,
    /// vcrd cannot do this. Blame: vcrd.
    Unsupported { declared: String, supported: Vec<&'static str> },
    /// vcrd could, but the caller said no. Blame: policy.
    PolicyRejected { declared: String, allowed: Vec<String> },
}

/// Breakpoint anchor for prototype question 5.
///
/// Policy is consulted independently of support, so a caller learns both facts at
/// once rather than discovering the second one only after fixing the first.
#[inline(never)]
pub fn select_algorithm(declared: &str, policy: &AlgPolicy) -> AlgDecision {
    if declared.eq_ignore_ascii_case("none") {
        return AlgDecision::Rejected(vec![AlgRejection::None]);
    }

    let mut rejections = Vec::new();

    let supported = Alg::from_name(declared);
    if supported.is_none() {
        rejections.push(AlgRejection::Unsupported {
            declared: declared.to_string(),
            supported: SUPPORTED_ALGS.to_vec(),
        });
    }
    if !policy.permits(declared) {
        rejections.push(AlgRejection::PolicyRejected {
            declared: declared.to_string(),
            allowed: policy.allowed_names(),
        });
    }

    match (supported, rejections.is_empty()) {
        (Some(alg), true) => AlgDecision::Use(alg),
        _ => AlgDecision::Rejected(rejections),
    }
}

#[derive(Clone, Debug, Default)]
pub struct JoseHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub cty: Option<String>,
    pub kid: Option<String>,
    pub jwk: Option<Value>,
    pub x5c: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct JwsParts {
    pub header: JoseHeader,
    pub header_json: Value,
    pub payload_json: Value,
    pub payload_bytes: Vec<u8>,
    pub signing_input: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum JwsParseError {
    NotCompact { segments: usize },
    Base64 { segment: &'static str },
    Json { segment: &'static str, message: String },
    HeaderAlgMissing,
}

/// Split a compact JWS and decode both JSON segments. No signature work here --
/// that is the proof suite's job, which is what keeps the format/suite seam real.
pub fn parse_compact(bytes: &[u8]) -> Result<JwsParts, JwsParseError> {
    let text = core::str::from_utf8(bytes)
        .map_err(|_| JwsParseError::Base64 { segment: "token" })?
        .trim();

    let segments: Vec<&str> = text.split('.').collect();
    if segments.len() != 3 {
        return Err(JwsParseError::NotCompact { segments: segments.len() });
    }
    let (h, p, s) = match segments.as_slice() {
        [h, p, s] => (*h, *p, *s),
        _ => return Err(JwsParseError::NotCompact { segments: segments.len() }),
    };

    let header_bytes = B64.decode(h).map_err(|_| JwsParseError::Base64 { segment: "header" })?;
    let payload_bytes = B64.decode(p).map_err(|_| JwsParseError::Base64 { segment: "payload" })?;
    // An empty signature segment is legal base64url for `alg: none` -- it must reach
    // algorithm selection and be rejected there, not be treated as a parse error.
    let signature = B64.decode(s).map_err(|_| JwsParseError::Base64 { segment: "signature" })?;

    let header_json: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwsParseError::Json { segment: "header", message: e.to_string() })?;
    let payload_json: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwsParseError::Json { segment: "payload", message: e.to_string() })?;

    let alg = header_json.get("alg").and_then(Value::as_str).ok_or(JwsParseError::HeaderAlgMissing)?;

    let header = JoseHeader {
        alg: alg.to_string(),
        typ: header_json.get("typ").and_then(Value::as_str).map(str::to_string),
        cty: header_json.get("cty").and_then(Value::as_str).map(str::to_string),
        kid: header_json.get("kid").and_then(Value::as_str).map(str::to_string),
        jwk: header_json.get("jwk").cloned(),
        x5c: header_json.get("x5c").cloned(),
    };

    let mut signing_input = Vec::with_capacity(h.len() + 1 + p.len());
    signing_input.extend_from_slice(h.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(p.as_bytes());

    Ok(JwsParts { header, header_json, payload_json, payload_bytes, signing_input, signature })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureCheck {
    Valid,
    Invalid,
    /// The resolved key cannot carry this algorithm. This is what catches
    /// "HMAC-signed with the issuer's public key".
    KeyTypeMismatch { key_kind: &'static str, expects: &'static str },
}

/// Verify a detached signing input against a resolved key under a *chosen* algorithm.
#[inline(never)]
pub fn verify_signature(alg: Alg, key: &VerifyKey, signing_input: &[u8], signature: &[u8]) -> SignatureCheck {
    use ed25519_dalek::Verifier as _;

    match (alg, key) {
        (Alg::EdDsa, VerifyKey::Ed25519(vk)) => {
            let sig_bytes: [u8; 64] = match signature.try_into() {
                Ok(b) => b,
                Err(_) => return SignatureCheck::Invalid,
            };
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            if vk.verify(signing_input, &sig).is_ok() {
                SignatureCheck::Valid
            } else {
                SignatureCheck::Invalid
            }
        }
        (Alg::Es256, VerifyKey::P256(vk)) => {
            use p256::ecdsa::signature::Verifier as _;
            match p256::ecdsa::Signature::from_slice(signature) {
                Ok(sig) if vk.verify(signing_input, &sig).is_ok() => SignatureCheck::Valid,
                _ => SignatureCheck::Invalid,
            }
        }
        (Alg::Es512, VerifyKey::P521(vk)) => {
            use p521::ecdsa::signature::Verifier as _;
            match p521::ecdsa::Signature::from_slice(signature) {
                Ok(sig) if vk.verify(signing_input, &sig).is_ok() => SignatureCheck::Valid,
                _ => SignatureCheck::Invalid,
            }
        }
        (Alg::Rs256, VerifyKey::Rsa(pk)) => {
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use rsa::signature::Verifier as _;
            let vk = VerifyingKey::<sha2::Sha256>::new((**pk).clone());
            match Signature::try_from(signature) {
                Ok(sig) if vk.verify(signing_input, &sig).is_ok() => SignatureCheck::Valid,
                _ => SignatureCheck::Invalid,
            }
        }
        (Alg::Hs256, VerifyKey::Octet(secret)) => {
            use hmac::{Hmac, Mac};
            let mut mac = match Hmac::<sha2::Sha256>::new_from_slice(secret) {
                Ok(m) => m,
                Err(_) => return SignatureCheck::Invalid,
            };
            mac.update(signing_input);
            if mac.verify_slice(signature).is_ok() {
                SignatureCheck::Valid
            } else {
                SignatureCheck::Invalid
            }
        }
        (alg, key) => SignatureCheck::KeyTypeMismatch {
            key_kind: key.kind(),
            expects: alg.required_key_kind(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_none_is_never_a_policy_question() {
        let d = select_algorithm("none", &AlgPolicy::allow_all());
        match d {
            AlgDecision::Rejected(r) => assert_eq!(r, vec![AlgRejection::None]),
            _ => panic!("alg: none was accepted"),
        }
    }

    #[test]
    fn unsupported_and_policy_rejected_are_distinct() {
        let unsupported = select_algorithm("ES256K", &AlgPolicy::allow_all());
        match unsupported {
            AlgDecision::Rejected(r) => {
                assert!(matches!(r.as_slice(), [AlgRejection::Unsupported { .. }]));
            }
            _ => panic!("ES256K was accepted"),
        }

        let policy = select_algorithm("ES256", &AlgPolicy::allow(vec!["EdDSA".into()]));
        match policy {
            AlgDecision::Rejected(r) => {
                assert!(matches!(r.as_slice(), [AlgRejection::PolicyRejected { .. }]));
            }
            _ => panic!("ES256 slipped past the allowlist"),
        }
    }

    #[test]
    fn both_reasons_are_reported_when_both_apply() {
        let d = select_algorithm("ES256K", &AlgPolicy::allow(vec!["EdDSA".into()]));
        match d {
            AlgDecision::Rejected(r) => assert_eq!(r.len(), 2, "collapsed two distinct reasons: {r:?}"),
            _ => panic!("accepted"),
        }
    }
}

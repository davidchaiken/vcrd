//! Key resolution and provenance (REQUIREMENTS §10; ARCHITECTURE §8).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::document::{EmbeddedKey, KeyHints};
use crate::finding::{
    Attribution, DidKeyProblem, Finding, FindingDetail, JwkProblem, KeySourceKind, Severity,
};
use crate::json::Json;
use crate::report::Phase;

/// A resolved public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(VerifyingKey),
}

impl PublicKey {
    /// The RFC 7638 JWK thumbprint, base64url-encoded.
    pub fn thumbprint(&self) -> String {
        match self {
            PublicKey::Ed25519(key) => {
                // The required members of an OKP key (RFC 8037 §2), in lexicographic
                // order with no whitespace (RFC 7638 §3.2).
                let x = URL_SAFE_NO_PAD.encode(key.as_bytes());
                let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
                URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
            }
        }
    }
}

/// A public key a credential carries about itself as a JWK (RFC 7517), parsed at the
/// parse boundary rather than kept as JSON (ARCHITECTURE §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwk {
    /// The RFC 7638 thumbprint, base64url-encoded, by which it is compared with the
    /// key resolution establishes (ARCHITECTURE §8).
    pub thumbprint: String,
    /// The key, when vcrd can use it: in milestone 1, an Ed25519 key (RFC 8037 §2).
    pub key: Option<PublicKey>,
}

/// For each key type, the members it requires, which are the members its RFC 7638
/// thumbprint covers, in lexicographic order (RFC 7638 §3.2; RFC 8037 §2). `oct` is
/// absent: its one required member is the secret.
const REQUIRED_MEMBERS: &[(&str, &[&str])] = &[
    ("EC", &["crv", "kty", "x", "y"]),
    ("OKP", &["crv", "kty", "x"]),
    ("RSA", &["e", "kty", "n"]),
];

/// The members that hold private or secret key material (RFC 7518 §6.2.2, §6.3.2,
/// §6.4.1; RFC 8037 §2).
#[cfg_attr(not(feature = "vc-jose"), allow(dead_code))]
pub(crate) const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

impl Jwk {
    /// Reads a JWK's public members. Whether it also carries private ones is
    /// inspect's question ([`PRIVATE_MEMBERS`]).
    #[cfg_attr(not(feature = "vc-jose"), allow(dead_code))]
    pub(crate) fn parse(json: &Json) -> Result<Jwk, JwkProblem> {
        if json.members().is_none() {
            return Err(JwkProblem::NotObject);
        }
        let kty = json
            .get("kty")
            .and_then(Json::as_str)
            .ok_or(JwkProblem::KtyMissing)?;
        if kty == "oct" {
            return Err(JwkProblem::Symmetric);
        }
        let required = REQUIRED_MEMBERS
            .iter()
            .find(|(k, _)| *k == kty)
            .map(|(_, members)| *members)
            .ok_or_else(|| JwkProblem::KtyUnknown {
                kty: kty.to_owned(),
            })?;
        let mut canonical = Vec::with_capacity(required.len());
        for &member in required {
            let value = json
                .get(member)
                .and_then(Json::as_str)
                .ok_or(JwkProblem::MemberMissing { member })?;
            // JSON string syntax, with no whitespace (RFC 7638 §3.3).
            let quote = |s: &str| serde_json::Value::String(s.to_owned()).to_string();
            canonical.push(format!("{}:{}", quote(member), quote(value)));
        }
        let canonical = format!("{{{}}}", canonical.join(","));
        let key = match (kty, json.get("crv").and_then(Json::as_str)) {
            ("OKP", Some("Ed25519")) => {
                let x = json.get("x").and_then(Json::as_str).unwrap_or_default();
                Some(ed25519_jwk(x).ok_or(JwkProblem::KeyInvalid)?)
            }
            _ => None,
        };
        Ok(Jwk {
            thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())),
            key,
        })
    }
}

/// An Ed25519 key's `x`: 32 bytes of strict base64url that decode to a point.
fn ed25519_jwk(x: &str) -> Option<PublicKey> {
    let bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
    let bytes: &[u8; 32] = bytes.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(bytes).ok().map(PublicKey::Ed25519)
}

/// Where the key used came from, and any key the credential offered about itself
/// (ARCHITECTURE §8). Reported whether verification succeeds or fails.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyProvenance {
    /// Absent when no key was used.
    pub source: Option<KeySource>,
    /// How the key was derived from its source, e.g. `did:key`.
    pub method: Option<&'static str>,
    /// The key used, as an RFC 7638 thumbprint.
    pub thumbprint: Option<String>,
    /// Present whenever the credential offered a key of its own.
    pub credential_key: Option<CredentialKey>,
}

/// An open set: consumers must accept values they do not recognize (ARCHITECTURE §8).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// Key material the caller passed in.
    CallerSupplied,
    /// Derived from the issuer identifier the credential names.
    IssuerIdentifier,
    /// A key the credential carries about itself, used only on the caller's opt-in.
    CredentialEmbedded,
}

impl KeySource {
    /// The stable name, so that a frontend need not match on this enumeration.
    pub fn as_str(self) -> &'static str {
        match self {
            KeySource::CallerSupplied => "caller_supplied",
            KeySource::IssuerIdentifier => "issuer_identifier",
            KeySource::CredentialEmbedded => "credential_embedded",
        }
    }
}

/// A key the credential offered about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialKey {
    /// Where it was, e.g. `header.jwk`.
    pub location: String,
    pub thumbprint: String,
    /// Whether it is the key used.
    pub matched: bool,
    /// Whether the signature verifies under it; absent when that cannot be tried.
    pub verifies_signature: Option<bool>,
}

#[derive(Default)]
pub(crate) struct Resolution {
    pub key: Option<PublicKey>,
    pub provenance: KeyProvenance,
    pub findings: Vec<Finding>,
    /// The key the credential carries about itself, when vcrd can use it, for the
    /// runner to fill in `credential_key.verifies_signature`.
    pub credential_key: Option<PublicKey>,
}

impl Resolution {
    fn failed(finding: Finding) -> Self {
        Resolution {
            findings: vec![finding],
            ..Resolution::default()
        }
    }
}

/// Finds the key for one proof (REQUIREMENTS §10). Milestone 1 has one source, the
/// issuer identifier when it is a `did:key`. A key the credential carries is
/// compared with that one, and refused when it is all there is.
pub(crate) fn resolve(hints: &KeyHints) -> Resolution {
    let mut resolution = match (hints.issuer.as_deref(), &hints.embedded) {
        (Some(issuer), _) => from_issuer(issuer),
        (None, None) => {
            return Resolution::failed(Finding::error(
                Phase::Verify,
                Attribution::Environment,
                FindingDetail::NoKeyMaterial {
                    consulted: vec![KeySourceKind::IssuerIdentifier],
                },
            ));
        }
        (None, Some(_)) => Resolution::default(),
    };
    if let Some(embedded) = &hints.embedded {
        compare_embedded(embedded, &mut resolution);
    }
    resolution
}

/// Records the carried key in the provenance (ARCHITECTURE §8): matched when its
/// thumbprint is that of the key derived from the issuer, refused when no key was
/// derived, and a warning when the two differ.
fn compare_embedded(embedded: &EmbeddedKey, resolution: &mut Resolution) {
    let thumbprint = &embedded.jwk.thumbprint;
    let derived = resolution.provenance.thumbprint.clone();
    let matched = derived.as_ref() == Some(thumbprint);
    match derived {
        // Refused, and reported as such rather than as "no key material"
        // (REQUIREMENTS §10). The opt-in that would allow it is the caller's.
        None => resolution.findings.push(Finding::error(
            Phase::Verify,
            Attribution::Policy,
            FindingDetail::EmbeddedKeyRefused {
                location: embedded.location,
            },
        )),
        Some(key) if !matched => resolution.findings.push(Finding::new(
            Phase::Verify,
            Attribution::Input,
            Severity::Warning,
            FindingDetail::CredentialKeyMismatch {
                location: embedded.location,
                credential_key: thumbprint.clone(),
                key,
            },
        )),
        Some(_) => {}
    }
    resolution.provenance.credential_key = Some(CredentialKey {
        location: embedded.location.to_owned(),
        thumbprint: thumbprint.clone(),
        matched,
        verifies_signature: None,
    });
    resolution.credential_key = embedded.jwk.key.clone();
}

/// The key the issuer identifier encodes, when it is a `did:key`.
fn from_issuer(issuer: &str) -> Resolution {
    let Some(identifier) = issuer.strip_prefix("did:key:") else {
        return Resolution::failed(Finding::error(
            Phase::Verify,
            Attribution::Vcrd,
            FindingDetail::IssuerMethodUnsupported {
                method: method_of(issuer),
            },
        ));
    };
    match decode_did_key(identifier) {
        Err(problem) => Resolution::failed(Finding::error(
            Phase::Verify,
            Attribution::Input,
            FindingDetail::DidKeyUndecodable { problem },
        )),
        Ok(DidKey::Unusable { codec, name }) => Resolution::failed(Finding::error(
            Phase::Verify,
            Attribution::Vcrd,
            FindingDetail::DidKeyCodecUnsupported { codec, name },
        )),
        Ok(DidKey::Usable(key, weak)) => {
            let thumbprint = key.thumbprint();
            let provenance = KeyProvenance {
                source: Some(KeySource::IssuerIdentifier),
                method: Some("did:key"),
                thumbprint: Some(thumbprint.clone()),
                credential_key: None,
            };
            if weak {
                // Checked at resolution, not left to the verifier (ARCHITECTURE §8).
                let finding = Finding::error(
                    Phase::Verify,
                    Attribution::Input,
                    FindingDetail::WeakKey { thumbprint },
                );
                Resolution {
                    provenance,
                    findings: vec![finding],
                    ..Resolution::default()
                }
            } else {
                Resolution {
                    key: Some(key),
                    provenance,
                    ..Resolution::default()
                }
            }
        }
    }
}

/// `did:web` for a DID, the scheme for any other URL.
fn method_of(identifier: &str) -> String {
    let mut parts = identifier.splitn(3, ':');
    match (parts.next(), parts.next()) {
        (Some("did"), Some(method)) => format!("did:{method}"),
        (Some(scheme), Some(_)) => scheme.to_owned(),
        _ => identifier.to_owned(),
    }
}

enum DidKey {
    /// The key, and whether it is weak.
    Usable(PublicKey, bool),
    /// A key type vcrd can name, or not, but cannot use.
    Unusable {
        codec: u64,
        name: Option<&'static str>,
    },
}

/// The multicodec key types ARCHITECTURE §8 lists that vcrd cannot yet use.
const NAMED_CODECS: &[(u64, &str)] = &[
    (0x1200, "p256-pub"),
    (0x1201, "p384-pub"),
    (0x1202, "p521-pub"),
    (0xe7, "secp256k1-pub"),
    (0x1205, "rsa-pub"),
];

const ED25519_PUB: u64 = 0xed;

/// Decodes the method-specific identifier of a `did:key`: multibase base58btc
/// (prefix `z`), then an unsigned-varint multicodec prefix naming the key type
/// (ARCHITECTURE §8).
fn decode_did_key(identifier: &str) -> Result<DidKey, DidKeyProblem> {
    let encoded = identifier
        .strip_prefix('z')
        .ok_or(DidKeyProblem::NotBase58btc)?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| DidKeyProblem::Base58Invalid)?;
    let (codec, key) =
        unsigned_varint::decode::u64(&bytes).map_err(|_| DidKeyProblem::CodecInvalid)?;
    if codec != ED25519_PUB {
        let name = NAMED_CODECS
            .iter()
            .find(|(c, _)| *c == codec)
            .map(|(_, n)| *n);
        return Ok(DidKey::Unusable { codec, name });
    }
    let key: &[u8; 32] = key.try_into().map_err(|_| DidKeyProblem::KeyLength {
        expected: 32,
        found: key.len(),
    })?;
    let key = VerifyingKey::from_bytes(key).map_err(|_| DidKeyProblem::PointInvalid)?;
    Ok(DidKey::Usable(PublicKey::Ed25519(key), key.is_weak()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 appendix A.2's public key.
    const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn did_key(codec_prefix: &[u8], key: &[u8]) -> String {
        let bytes = [codec_prefix, key].concat();
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    fn rfc8037_key() -> [u8; 32] {
        URL_SAFE_NO_PAD
            .decode(RFC8037_X)
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn thumbprint_matches_rfc8037_a3() {
        let key = PublicKey::Ed25519(VerifyingKey::from_bytes(&rfc8037_key()).unwrap());
        assert_eq!(
            key.thumbprint(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn resolves_an_ed25519_did_key() {
        let hints = KeyHints {
            issuer: Some(did_key(&[0xed, 0x01], &rfc8037_key())),
            kid: None,
            embedded: None,
        };
        let resolution = resolve(&hints);
        assert!(resolution.findings.is_empty(), "{:?}", resolution.findings);
        assert_eq!(
            resolution.provenance.source,
            Some(KeySource::IssuerIdentifier)
        );
        assert_eq!(
            resolution.provenance.thumbprint.as_deref(),
            Some("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
        );
        assert!(resolution.key.is_some());
    }

    #[test]
    fn names_a_key_type_it_cannot_use() {
        let hints = KeyHints {
            issuer: Some(did_key(&[0x80, 0x24], &[2; 33])),
            kid: None,
            embedded: None,
        };
        let resolution = resolve(&hints);
        let [finding] = resolution.findings.as_slice() else {
            panic!("one finding")
        };
        assert_eq!(finding.attribution, Attribution::Vcrd);
        assert!(matches!(
            finding.detail,
            FindingDetail::DidKeyCodecUnsupported {
                codec: 0x1200,
                name: Some("p256-pub")
            }
        ));
    }

    fn jwk(text: &str) -> Result<Jwk, JwkProblem> {
        Jwk::parse(&Json::parse(text.as_bytes()).unwrap())
    }

    /// RFC 7638 §3.1's example, whose `alg` and `kid` the thumbprint leaves out.
    #[test]
    fn jwk_thumbprint_matches_rfc7638_3_1() {
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        let key = jwk(&format!(
            r#"{{"kty": "RSA", "n": "{n}", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"}}"#
        ))
        .unwrap();
        assert_eq!(
            key.thumbprint,
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
        assert_eq!(key.key, None);
    }

    /// The same thumbprint whether the key arrives as a JWK or a `did:key`.
    #[test]
    fn ed25519_jwk_matches_rfc8037_a3() {
        let key = jwk(&format!(
            r#"{{"kty": "OKP", "crv": "Ed25519", "x": "{RFC8037_X}"}}"#
        ))
        .unwrap();
        assert_eq!(
            key.thumbprint,
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        assert_eq!(key.key.unwrap().thumbprint(), key.thumbprint);
    }

    #[test]
    fn names_what_is_wrong_with_a_jwk() {
        assert_eq!(jwk("[]"), Err(JwkProblem::NotObject));
        assert_eq!(jwk(r#"{"kty": 1}"#), Err(JwkProblem::KtyMissing));
        assert_eq!(
            jwk(r#"{"kty": "oct", "k": "c2VjcmV0"}"#),
            Err(JwkProblem::Symmetric)
        );
        assert_eq!(
            jwk(r#"{"kty": "AKP"}"#),
            Err(JwkProblem::KtyUnknown { kty: "AKP".into() })
        );
        assert_eq!(
            jwk(r#"{"kty": "EC", "crv": "P-256", "x": "AA"}"#),
            Err(JwkProblem::MemberMissing { member: "y" })
        );
        assert_eq!(
            jwk(r#"{"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}"#),
            Err(JwkProblem::KeyInvalid)
        );
    }

    fn with_embedded(issuer: Option<String>, x: &str) -> Resolution {
        let jwk = jwk(&format!(
            r#"{{"kty": "OKP", "crv": "Ed25519", "x": "{x}"}}"#
        ))
        .unwrap();
        resolve(&KeyHints {
            issuer,
            kid: None,
            embedded: Some(EmbeddedKey {
                location: "header.jwk",
                jwk,
            }),
        })
    }

    #[test]
    fn an_embedded_key_equal_to_the_did_key_matches() {
        let issuer = did_key(&[0xed, 0x01], &rfc8037_key());
        let resolution = with_embedded(Some(issuer), RFC8037_X);
        assert!(resolution.findings.is_empty(), "{:?}", resolution.findings);
        let credential_key = resolution.provenance.credential_key.unwrap();
        assert!(credential_key.matched);
        assert_eq!(credential_key.location, "header.jwk");
        assert!(resolution.key.is_some());
    }

    #[test]
    fn an_embedded_key_unlike_the_did_key_is_a_warning() {
        let issuer = did_key(&[0xed, 0x01], &rfc8037_key());
        let other = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let other = URL_SAFE_NO_PAD.encode(other.as_bytes());
        let resolution = with_embedded(Some(issuer), &other);
        let [finding] = resolution.findings.as_slice() else {
            panic!("one finding: {:?}", resolution.findings)
        };
        assert_eq!(finding.code, "verify.credential_key_mismatch");
        assert_eq!(finding.severity, Severity::Warning);
        assert!(!resolution.provenance.credential_key.unwrap().matched);
        assert!(resolution.key.is_some(), "the issuer's key is still used");
    }

    #[test]
    fn an_embedded_key_alone_is_refused_by_policy() {
        let resolution = with_embedded(None, RFC8037_X);
        let [finding] = resolution.findings.as_slice() else {
            panic!("one finding: {:?}", resolution.findings)
        };
        assert_eq!(finding.code, "verify.embedded_key_refused");
        assert_eq!(finding.attribution, Attribution::Policy);
        assert_eq!(resolution.provenance.source, None);
        assert!(resolution.key.is_none());
        assert!(resolution.credential_key.is_some());
    }

    #[test]
    fn names_the_method_of_an_issuer_it_cannot_resolve() {
        assert_eq!(method_of("did:web:example.com"), "did:web");
        assert_eq!(method_of("https://example.com/issuer"), "https");
    }
}

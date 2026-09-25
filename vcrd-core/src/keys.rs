//! Key resolution and provenance (REQUIREMENTS §10; ARCHITECTURE §8).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::document::KeyHints;
use crate::finding::{Attribution, DidKeyProblem, Finding, FindingDetail, KeySourceKind};
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

pub(crate) struct Resolution {
    pub key: Option<PublicKey>,
    pub provenance: KeyProvenance,
    pub findings: Vec<Finding>,
}

impl Resolution {
    fn failed(finding: Finding) -> Self {
        Resolution {
            key: None,
            provenance: KeyProvenance::default(),
            findings: vec![finding],
        }
    }
}

/// Finds the key for one proof. Milestone 1 has one source, the issuer identifier
/// when it is a `did:key` (REQUIREMENTS §10).
pub(crate) fn resolve(hints: &KeyHints) -> Resolution {
    let Some(issuer) = hints.issuer.as_deref() else {
        return Resolution::failed(Finding::error(
            Phase::Verify,
            Attribution::Environment,
            FindingDetail::NoKeyMaterial {
                consulted: vec![KeySourceKind::IssuerIdentifier],
            },
        ));
    };
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
                    key: None,
                    provenance,
                    findings: vec![finding],
                }
            } else {
                Resolution {
                    key: Some(key),
                    provenance,
                    findings: Vec::new(),
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

    #[test]
    fn names_the_method_of_an_issuer_it_cannot_resolve() {
        assert_eq!(method_of("did:web:example.com"), "did:web");
        assert_eq!(method_of("https://example.com/issuer"), "https");
    }
}

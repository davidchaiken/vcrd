//! Key resolution and provenance (REQUIREMENTS §10; ARCHITECTURE §8).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::document::{EmbeddedKey, KeyHints};
use crate::finding::{
    Attribution, DidKeyProblem, EmbeddedKeyRef, Finding, FindingDetail, JwkProblem, KeyRef,
    KeySourceKind, Severity, WeakKeyCriterion,
};
use crate::json::Json;
use crate::report::{Phase, ProofOutcome};

/// A resolved public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(VerifyingKey),
}

impl PublicKey {
    /// The key as a JWK: the members its thumbprint covers.
    pub fn jwk(&self) -> PublicJwk {
        match self {
            // The required members of an OKP key (RFC 8037 §2).
            PublicKey::Ed25519(key) => PublicJwk {
                members: vec![
                    ("crv", "Ed25519".to_owned()),
                    ("kty", "OKP".to_owned()),
                    ("x", URL_SAFE_NO_PAD.encode(key.as_bytes())),
                ],
            },
        }
    }

    /// The RFC 7638 JWK thumbprint, base64url-encoded.
    pub fn thumbprint(&self) -> String {
        self.jwk().thumbprint()
    }
}

/// A public key as a JWK (RFC 7517): the members its RFC 7638 thumbprint covers, in
/// that RFC's lexicographic order, each value as written. Shown beside a thumbprint,
/// so that a reader can see which key it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicJwk {
    pub members: Vec<(&'static str, String)>,
}

impl PublicJwk {
    /// The RFC 7638 thumbprint, base64url-encoded: SHA-256 over the members as a JSON
    /// object with no whitespace (RFC 7638 §3.2–3.3).
    pub fn thumbprint(&self) -> String {
        let quote = |s: &str| serde_json::Value::String(s.to_owned()).to_string();
        let members: Vec<String> = self
            .members
            .iter()
            .map(|(name, value)| format!("{}:{}", quote(name), quote(value)))
            .collect();
        let canonical = format!("{{{}}}", members.join(","));
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
    }
}

/// A public key a credential carries about itself as a JWK (RFC 7517), parsed at the
/// parse boundary rather than kept as JSON (ARCHITECTURE §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwk {
    /// Its public members, which the thumbprint covers.
    pub public: PublicJwk,
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
        let mut members = Vec::with_capacity(required.len());
        for &member in required {
            let value = json
                .get(member)
                .and_then(Json::as_str)
                .ok_or(JwkProblem::MemberMissing { member })?;
            members.push((member, value.to_owned()));
        }
        let public = PublicJwk { members };
        let key = match (kty, json.get("crv").and_then(Json::as_str)) {
            ("OKP", Some("Ed25519")) => {
                let x = json.get("x").and_then(Json::as_str).unwrap_or_default();
                Some(ed25519_jwk(x).ok_or(JwkProblem::KeyInvalid)?)
            }
            _ => None,
        };
        Ok(Jwk {
            thumbprint: public.thumbprint(),
            public,
            key,
        })
    }
}

/// An Ed25519 key's `x`: 32 bytes of strict base64url that decode to a point.
fn ed25519_jwk(x: &str) -> Option<PublicKey> {
    let bytes = URL_SAFE_NO_PAD.decode(x).ok()?;
    let bytes: &[u8; 32] = bytes.as_slice().try_into().ok()?;
    ed25519_key(bytes).ok().map(PublicKey::Ed25519)
}

/// An Ed25519 public key, decoded as RFC 8032 §5.1.3 decodes one. `curve25519-dalek`
/// also decodes y at or above p, and x = 0 with the sign bit set, so the point is
/// encoded again and compared with the bytes.
fn ed25519_key(bytes: &[u8; 32]) -> Result<VerifyingKey, DidKeyProblem> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| DidKeyProblem::PointInvalid)?;
    if key.to_edwards().compress().as_bytes() != bytes {
        return Err(DidKeyProblem::PointNotCanonical);
    }
    Ok(key)
}

/// Where the deciding proof key came from, and the embedded key, if any (ARCHITECTURE
/// §8). Reported whether verification succeeds or fails.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyProvenance {
    /// Present also when the key is refused, as a weak key is, so that the finding's
    /// key can be told apart; absent when no key could decide the outcome.
    pub source: Option<KeySource>,
    /// How the key was derived from its source, e.g. `did:key`.
    pub method: Option<&'static str>,
    /// The deciding proof key, as an RFC 7638 thumbprint.
    pub thumbprint: Option<String>,
    /// The deciding proof key, as a JWK: what the thumbprint is of.
    pub jwk: Option<PublicJwk>,
    /// Present whenever the credential carries a key about its own proof that vcrd
    /// can read.
    pub embedded_key: Option<EmbeddedKeyReport>,
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

/// The embedded key: a key the credential carries about its own proof (ARCHITECTURE §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedKeyReport {
    /// Where it was, e.g. `header.jwk`.
    pub location: String,
    pub thumbprint: String,
    /// Its public members, as the credential carries them.
    pub jwk: PublicJwk,
    /// Whether it is the issuer key; absent when there is no issuer key to compare it
    /// with.
    pub same_as_issuer_key: Option<bool>,
    /// The proof's result with it as the proof key, under the same algorithm policy and
    /// key-type binding as the deciding proof.
    pub proof: ProofOutcome,
}

#[derive(Default)]
pub(crate) struct Resolution {
    pub key: Option<PublicKey>,
    pub provenance: KeyProvenance,
    pub findings: Vec<Finding>,
    /// The embedded key, when vcrd can use it as a proof key, for the runner's proof
    /// with it.
    pub embedded_key: Option<PublicKey>,
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

/// Records the embedded key in the provenance (ARCHITECTURE §8): the same key as the
/// issuer key when their thumbprints are equal, refused when there is no issuer key,
/// and a warning when the two differ. The runner adds its proof's result.
fn compare_embedded(embedded: &EmbeddedKey, resolution: &mut Resolution) {
    let thumbprint = &embedded.jwk.thumbprint;
    let provenance = &resolution.provenance;
    let issuer = provenance
        .source
        .filter(|s| *s == KeySource::IssuerIdentifier)
        .zip(provenance.thumbprint.clone());
    let same_as_issuer_key = issuer.as_ref().map(|(_, t)| t == thumbprint);
    let method = provenance.method;
    match issuer {
        // Refused, and reported as such rather than as "no key material"
        // (REQUIREMENTS §10). The opt-in that would allow it is the caller's.
        None => resolution.findings.push(Finding::error(
            Phase::Verify,
            Attribution::Policy,
            FindingDetail::EmbeddedKeyRefused {
                location: embedded.location,
            },
        )),
        Some((source, key)) if same_as_issuer_key == Some(false) => {
            resolution.findings.push(Finding::new(
                Phase::Verify,
                Attribution::Input,
                Severity::Warning,
                FindingDetail::EmbeddedKeyMismatch {
                    embedded_key: EmbeddedKeyRef {
                        location: embedded.location,
                        thumbprint: thumbprint.clone(),
                    },
                    key: KeyRef {
                        source,
                        method,
                        thumbprint: key,
                    },
                },
            ));
        }
        Some(_) => {}
    }
    resolution.provenance.embedded_key = Some(EmbeddedKeyReport {
        location: embedded.location.to_owned(),
        thumbprint: thumbprint.clone(),
        jwk: embedded.jwk.public.clone(),
        same_as_issuer_key,
        proof: ProofOutcome::NotAttempted,
    });
    resolution.embedded_key = embedded.jwk.key.clone();
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
        Ok(DidKey::NotForSigning { codec, name }) => Resolution::failed(Finding::error(
            Phase::Verify,
            Attribution::Input,
            FindingDetail::DidKeyNotForSigning { codec, name },
        )),
        Ok(DidKey::Usable(key, weak)) => {
            let jwk = key.jwk();
            let thumbprint = jwk.thumbprint();
            let provenance = KeyProvenance {
                source: Some(KeySource::IssuerIdentifier),
                method: Some("did:key"),
                thumbprint: Some(thumbprint.clone()),
                jwk: Some(jwk),
                embedded_key: None,
            };
            if weak {
                // Checked at resolution, not left to the verifier (ARCHITECTURE §8).
                let finding = Finding::error(
                    Phase::Verify,
                    Attribution::Input,
                    FindingDetail::WeakKey {
                        key: KeyRef {
                            source: KeySource::IssuerIdentifier,
                            method: Some("did:key"),
                            thumbprint,
                        },
                        criterion: WeakKeyCriterion::SmallOrder,
                    },
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
    /// A key-agreement key, which no verifier may use for a signature.
    NotForSigning { codec: u64, name: &'static str },
}

/// The multicodec key types ARCHITECTURE §8 lists that vcrd cannot yet use.
const NAMED_CODECS: &[(u64, &str)] = &[
    (0x1200, "p256-pub"),
    (0x1201, "p384-pub"),
    (0x1202, "p521-pub"),
    (0xe7, "secp256k1-pub"),
    (0x1205, "rsa-pub"),
    (0x1203, "ed448-pub"),
];

/// The multicodec key types for key agreement, which RFC 8037 §3.2 forbids for signing.
const KEY_AGREEMENT_CODECS: &[(u64, &str)] = &[(0xec, "x25519-pub"), (0x1204, "x448-pub")];

const ED25519_PUB: u64 = 0xed;

/// Decodes the method-specific identifier of a `did:key`: multibase base58btc
/// (prefix `z`), then an unsigned-varint multicodec prefix naming the key type
/// (ARCHITECTURE §8).
fn decode_did_key(identifier: &str) -> Result<DidKey, DidKeyProblem> {
    // did:key v0.9's Create algorithm reads the component before the multibase value
    // as a version; its syntax has none.
    if identifier.contains(':') {
        return Err(DidKeyProblem::VersionPresent);
    }
    let encoded = identifier
        .strip_prefix('z')
        .ok_or(DidKeyProblem::NotBase58btc)?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| DidKeyProblem::Base58Invalid)?;
    let (codec, key) =
        unsigned_varint::decode::u64(&bytes).map_err(|_| DidKeyProblem::CodecInvalid)?;
    if let Some(&(codec, name)) = KEY_AGREEMENT_CODECS.iter().find(|(c, _)| *c == codec) {
        return Ok(DidKey::NotForSigning { codec, name });
    }
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
    let key = ed25519_key(key)?;
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

    /// Each way the did:key v0.9 decoding can fail is named: the multibase prefix
    /// (Create, step 3), the base58btc and the multicodec header (Decode Public Key),
    /// the key's length and its encoding (Signature Method Creation, steps 3 and 4).
    #[test]
    fn names_what_is_wrong_with_a_did_key() {
        let key = rfc8037_key();
        // y = 2, which no point on the curve has.
        let mut not_a_point = [0; 32];
        not_a_point[0] = 2;
        assert_eq!(undecodable("did:key:u7QE"), DidKeyProblem::NotBase58btc);
        assert_eq!(undecodable("did:key:z0OIl"), DidKeyProblem::Base58Invalid);
        assert_eq!(
            undecodable(&did_key(&[0x80], &[])),
            DidKeyProblem::CodecInvalid
        );
        assert_eq!(
            undecodable(&did_key(&[0xed, 0x01], &key[..31])),
            DidKeyProblem::KeyLength {
                expected: 32,
                found: 31
            }
        );
        assert_eq!(
            undecodable(&did_key(&[0xed, 0x01], &not_a_point)),
            DidKeyProblem::PointInvalid
        );
    }

    /// RFC 8032 §5.1.3: decoding fails for y at or above p (step 1), and for x = 0 with
    /// the sign bit set (step 4). `curve25519-dalek` decodes both. y = p + 3 is the
    /// point whose y is 3, which is not weak.
    #[test]
    fn rejects_a_key_not_encoded_as_rfc8032_requires() {
        assert_eq!(
            undecodable(&did_key(&[0xed, 0x01], &y_above_p(3))),
            DidKeyProblem::PointNotCanonical
        );
        let mut y_is_3 = [0; 32];
        y_is_3[0] = 3;
        let resolution = resolve_issuer(&did_key(&[0xed, 0x01], &y_is_3));
        assert!(resolution.findings.is_empty(), "{:?}", resolution.findings);
        // The identity point, whose x is 0, with the sign bit set.
        let mut identity = [0; 32];
        identity[0] = 1;
        identity[31] = 0x80;
        assert_eq!(
            undecodable(&did_key(&[0xed, 0x01], &identity)),
            DidKeyProblem::PointNotCanonical
        );
        let x = URL_SAFE_NO_PAD.encode(y_above_p(3));
        assert_eq!(
            jwk(&format!(
                r#"{{"kty": "OKP", "crv": "Ed25519", "x": "{x}"}}"#
            )),
            Err(JwkProblem::KeyInvalid)
        );
    }

    /// RFC 8037 §3.2: X25519 and X448 keys MUST NOT be used for signing, so a `did:key`
    /// holding one is the input's error, not a key type vcrd lacks. An Ed448 key is one
    /// vcrd lacks, and is named.
    #[test]
    fn a_key_agreement_key_is_not_for_signing() {
        for (prefix, length, expected_codec, expected_name) in [
            (&[0xec, 0x01][..], 32, 0xec, "x25519-pub"),
            (&[0x84, 0x24][..], 56, 0x1204, "x448-pub"),
        ] {
            let finding = one_finding(&did_key(prefix, &vec![9; length]));
            assert_eq!(finding.attribution, Attribution::Input, "{finding:?}");
            assert!(
                matches!(
                    finding.detail,
                    FindingDetail::DidKeyNotForSigning { codec, name }
                        if codec == expected_codec && name == expected_name
                ),
                "{finding:?}"
            );
        }
        let finding = one_finding(&did_key(&[0x83, 0x24], &[9; 57]));
        assert_eq!(finding.attribution, Attribution::Vcrd);
        assert!(
            matches!(
                finding.detail,
                FindingDetail::DidKeyCodecUnsupported {
                    codec: 0x1203,
                    name: Some("ed448-pub")
                }
            ),
            "{finding:?}"
        );
    }

    /// did:key v0.9's Create algorithm reads a version before the multibase value; its
    /// syntax has none. The version is named, rather than taken for the value.
    #[test]
    fn names_a_version_before_the_multibase_value() {
        let issuer = did_key(&[0xed, 0x01], &rfc8037_key());
        let versioned = issuer.replacen("did:key:", "did:key:1:", 1);
        assert_eq!(undecodable(&versioned), DidKeyProblem::VersionPresent);
    }

    fn resolve_issuer(issuer: &str) -> Resolution {
        resolve(&KeyHints {
            issuer: Some(issuer.to_owned()),
            kid: None,
            embedded: None,
        })
    }

    /// The one finding resolving this issuer reports.
    fn one_finding(issuer: &str) -> Finding {
        let resolution = resolve_issuer(issuer);
        let [finding] = resolution.findings.as_slice() else {
            panic!("{issuer}: {:?}", resolution.findings)
        };
        finding.clone()
    }

    /// Why this issuer's `did:key` does not decode, a problem of the input's.
    fn undecodable(issuer: &str) -> DidKeyProblem {
        match one_finding(issuer) {
            Finding {
                detail: FindingDetail::DidKeyUndecodable { problem },
                attribution: Attribution::Input,
                ..
            } => problem,
            other => panic!("{issuer}: {other:?}"),
        }
    }

    /// y = p + `excess`, at or above p = 2^255 - 19, with the sign bit clear.
    fn y_above_p(excess: u8) -> [u8; 32] {
        let mut bytes = [0xff; 32];
        bytes[0] = 0xed + excess;
        bytes[31] = 0x7f;
        bytes
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
    fn an_embedded_key_equal_to_the_did_key_is_the_same_key() {
        let issuer = did_key(&[0xed, 0x01], &rfc8037_key());
        let resolution = with_embedded(Some(issuer), RFC8037_X);
        assert!(resolution.findings.is_empty(), "{:?}", resolution.findings);
        let embedded = resolution.provenance.embedded_key.unwrap();
        assert_eq!(embedded.same_as_issuer_key, Some(true));
        assert_eq!(embedded.location, "header.jwk");
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
        assert_eq!(finding.code, "verify.embedded_key_mismatch");
        assert_eq!(finding.severity, Severity::Warning);
        let embedded = resolution.provenance.embedded_key.unwrap();
        assert_eq!(embedded.same_as_issuer_key, Some(false));
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
        assert!(resolution.embedded_key.is_some());
    }

    #[test]
    fn names_the_method_of_an_issuer_it_cannot_resolve() {
        assert_eq!(method_of("did:web:example.com"), "did:web");
        assert_eq!(method_of("https://example.com/issuer"), "https");
    }
}
